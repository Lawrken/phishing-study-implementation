"""A saturated workload must not discard the durable local health probe."""
import json
from pathlib import Path
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import dns.message
import dns.query
import dns.rcode
from study import logging_resolver as resolver
from study.public_pilot import logged_health_probe


class ResolverCapacityTests(unittest.TestCase):
    def test_only_well_formed_exact_reserved_a_query_uses_health_capacity(self):
        self.assertTrue(resolver.health_request(dns.message.make_query('health.controls.test','A').to_wire()))
        for name, kind in [('health.controls.test','AAAA'),('prefix.health.controls.test','A'),
                           ('health.controls.test.example.com','A'),('normal.example.com','A')]:
            with self.subTest(name=name,kind=kind):
                self.assertFalse(resolver.health_request(dns.message.make_query(name,kind).to_wire()))
        self.assertFalse(resolver.health_request(b'bad'))
        query=dns.message.make_query('health.controls.test','A')
        self.assertFalse(resolver.health_request(dns.message.make_response(query).to_wire()))

    def test_logged_refusal_completes_while_all_workload_handlers_are_busy(self):
        entered,released=threading.Event(),threading.Event()
        original=resolver.process_query
        def forward(query,upstream):
            entered.set()
            if not released.wait(3):raise RuntimeError('test_controller_did_not_release')
            response=dns.message.make_response(query);response.set_rcode(dns.rcode.NXDOMAIN)
            return response
        def process(raw,**kwargs):return original(raw,forwarder=forward,**kwargs)
        with tempfile.TemporaryDirectory() as folder, (Path(folder)/'queries.jsonl').open('w') as handle:
            log=resolver.EventLog(handle,None)
            server=resolver.UDPServer(('127.0.0.1',0),resolver.UDPHandler)
            server.log=log;server.mode='public-web';server.allowed_hosts=frozenset();server.upstream='127.0.0.53'
            server.semaphore=threading.BoundedSemaphore(1)
            server.health_semaphore=threading.BoundedSemaphore(1)
            thread=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.02},daemon=True)
            try:
                with patch.object(resolver,'process_query',side_effect=process), socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as workload:
                    thread.start()
                    workload.sendto(dns.message.make_query('normal.example.com','A').to_wire(),server.server_address)
                    self.assertTrue(entered.wait(1),'workload receiver did not start')
                    health=dns.message.make_query('health.controls.test','A')
                    response=dns.query.udp(health,'127.0.0.1',port=server.server_address[1],timeout=1.5)
                    self.assertEqual(response.rcode(),dns.rcode.REFUSED)
                    self.assertFalse(released.is_set(),'health passed only after the workload was released')
                    rows=[json.loads(line) for line in (Path(folder)/'queries.jsonl').read_text().splitlines()]
                    self.assertTrue(any(row.get('query_id')==health.id and row.get('status')=='refused' for row in rows))
                    released.set()
                    self.assertTrue(server.semaphore.acquire(timeout=2))
                    self.assertTrue(server.health_semaphore.acquire(timeout=2))
                    server.semaphore.release();server.health_semaphore.release()
            finally:
                released.set()
                if thread.is_alive():server.shutdown()
                server.server_close();thread.join(timeout=1)

    def test_health_reply_is_not_sent_when_durable_logging_fails(self):
        query=dns.message.make_query('health.controls.test','A')
        connection=Mock();handle=Mock();handle.write.side_effect=OSError('storage failed')
        log=resolver.EventLog(handle,None)
        server=SimpleNamespace(log=log,upstream='127.0.0.53',allowed_hosts=frozenset(),mode='public-web')
        handler=SimpleNamespace(server=server,request=(query.to_wire(),connection),client_address=('127.0.0.1',12345))
        with self.assertRaises(resolver.LoggingFailure):resolver.UDPHandler.handle(handler)
        connection.sendto.assert_not_called()
        self.assertTrue(log.failed.is_set());self.assertTrue(log.stop.is_set())

    def test_full_health_pool_is_bounded_and_never_borrows_workload_slots(self):
        with tempfile.TemporaryDirectory() as folder, (Path(folder)/'queries.jsonl').open('w') as handle:
            server=resolver.UDPServer(('127.0.0.1',0),resolver.UDPHandler)
            server.log=resolver.EventLog(handle,None)
            server.semaphore=threading.BoundedSemaphore(1);server.health_semaphore=threading.BoundedSemaphore(1)
            self.assertTrue(server.health_semaphore.acquire(blocking=False))
            try:
                server.process_request((dns.message.make_query('health.controls.test','A').to_wire(),server.socket),('127.0.0.1',123))
                self.assertTrue(server.semaphore.acquire(blocking=False))
                server.semaphore.release()
                rows=[json.loads(line) for line in (Path(folder)/'queries.jsonl').read_text().splitlines()]
                self.assertEqual(rows[-1]['pool'],'health')
                self.assertEqual(rows[-1]['event'],'capacity_rejected')
            finally:server.health_semaphore.release();server.server_close()

    def test_health_controller_requires_the_actual_query_id_in_durable_log(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'queries.jsonl'
            for matches in (True,False):
                path.write_text('')
                def reply(query,*args,**kwargs):
                    result=dns.message.make_response(query);result.set_rcode(dns.rcode.REFUSED)
                    row={'event':'query','status':'refused','hostname':'<refused>','rcode':'REFUSED',
                         'query_id':query.id if matches else query.id^1}
                    path.write_text(json.dumps(row)+'\n')
                    return result
                with patch('dns.query.udp',side_effect=reply):
                    if matches:self.assertEqual(logged_health_probe(path)['rcode'],'REFUSED')
                    else:
                        with self.assertRaisesRegex(ValueError,'durable_health_query_log_missing'):logged_health_probe(path)

if __name__=='__main__':unittest.main()
