import socket
import time

import dns
import dns.resolver
import dnsq
from mock import Mock, patch
from nose.tools import eq_, ok_, assert_raises


def test_dns_query():
    # note: we're not mocking DNS, i.e. you need to have internet connection to run this
    # test. perhaps we should change it?
    answer = dnsq.query_dns('mailgun.net', 'mx')
    eq_(2, len(answer))
    ok_("10 mxa.mailgun.org." in answer)
    ok_("10 mxb.mailgun.org." in answer)

    # test TXT concatenation:
    with patch.object(dns.resolver.Resolver, 'query') as query:
        query.reset_mock()
        query.return_value = [Mock()]
        query.return_value[0].to_text = Mock(return_value="\"Hello\" \"world\"")
        eq_(['Helloworld'], dnsq.query_dns('mailgun.us', 'txt'))

        # specify the name server
        eq_(['Helloworld'], dnsq.query_dns('mailgun.us', 'txt',
                                           name_srv='ns1.com'))
        # socket error
        query.side_effect = socket.error
        eq_([], dnsq.query_dns('mailgun.us', 'txt'))

        # test fallback to default nameserver
        query.side_effect = dns.exception.Timeout
        eq_([], dnsq.query_dns('mailgun.us', 'txt', name_srv='ns1.com'))

    # test errors:
    with patch.object(dns.resolver.Resolver, 'query') as query:
        query.side_effect = dns.resolver.NoNameservers()
        eq_([], dnsq.query_dns('mailgun.net', 'mx'))
        query.side_effect = dns.resolver.NXDOMAIN()
        eq_([], dnsq.query_dns('mailgun.net', 'mx'))
        query.side_effect = dns.resolver.NoAnswer()
        eq_([], dnsq.query_dns('mailgun.net', 'mx'))


def test_mx_lookup():
    # query against live DNS server:
    answer = dnsq.mx_hosts_for('gmail.com')[0]
    ok_('google.com' in answer)

    with patch.object(dnsq, '_get_default_resolver') as get_resolver:
        r = Mock()
        get_resolver.return_value = r

        # makes a fake MX reply
        def fake_mx(name):
            class FakeEntry(object):
                @property
                def preference(self): return 1

                @property
                def exchange(self):
                    class Value(object):
                        def to_text(self): return name

                    return Value()

            return FakeEntry()

        # test MX timeout failure:
        with patch.object(r, 'query', Mock(side_effect=dns.exception.Timeout)):
            eq_([], dnsq.mx_hosts_for('host.com'))

        # test querying an invalid domain:
        with patch.object(r, 'query',
                          Mock(side_effect=dns.resolver.NXDOMAIN())):
            eq_([], dnsq.mx_hosts_for('invalid-siteeeee.com'))

        # test querying a domain without MX:
        with patch.object(r, 'query',
                          Mock(side_effect=dns.resolver.NoAnswer())):
            eq_(['host.com'], dnsq.mx_hosts_for('host.com'))

        # test querying a domain with MX:
        with patch.object(r, 'query') as query_mock:
            query_mock.return_value = [fake_mx('mx.host.com.'),
                                       fake_mx('mx2.host.com.')]
            eq_(set(['mx.host.com', 'mx2.host.com']),
                set(dnsq.mx_hosts_for('host.com')))

        # test failure:
        with patch.object(r, 'query', Mock(side_effect=Exception('bam!'))):
            assert_raises(Exception, dnsq.mx_hosts_for, 'host.com')

        # test dns failure
        with patch.object(dnsq, '_exec_query') as exec_query:
            exec_query.side_effect = dns.exception.Timeout
            assert_raises(Exception, dnsq.mx_hosts_for, 'host.com')


@patch.object(dnsq, '_get_primary_nameserver', Mock(return_value='ns.com'))
@patch.object(dnsq, 'query_dns')
def test_spf_record_for(dns):
    # No SPF records
    dns.return_value = ["blah"]
    eq_('', dnsq.spf_record_for('host.com'))

    # Multiple SPF records
    dns.return_value = ["v=spf1 +all", "blah", "v=spf1 -all"]
    eq_('', dnsq.spf_record_for('host.com'))

    # OK - one SPF record
    dns.return_value = ["blah", "v=spf1 +all", "blahblah"]
    eq_("v=spf1 +all", dnsq.spf_record_for('host.com'))


def test_ptr_record_for():
    eq_(dnsq.ptr_record_for('127.0.0.1'), 'localhost')

    # Ev: this one actually "calls the internet". Which is pretty bad from the maintenance
    # perspective, but I am not sure how else to reliably cover it:
    eq_(dnsq.ptr_record_for('50.56.21.178'),
        socket.gethostbyaddr('50.56.21.178')[0])

    # lets test caching:
    with patch.object(dnsq, 'query_dns') as query_dns:
        query_dns.return_value = []
        eq_(None, dnsq.ptr_record_for('1.1.1.1'))
        then = time.time()  # measure time
        eq_(None, dnsq.ptr_record_for('1.1.1.1'))
        eq_(1, query_dns.call_count, "query_dns() should be called only once!" \
                                     "... otherwise the PTR cache is not working!")

        time_elapsed = (time.time() - then)
        ok_(time_elapsed < 0.001,
            "PTR lookup was too slow. The cache is not working?")

        query_dns.side_effect = Exception('Bam!')
        eq_(None, dnsq.ptr_record_for('1.1.1.2'))


@patch.object(dnsq, 'query_dns')
def test_get_primary_nameserver(query_dns):
    query_dns.side_effect = [[], ['srv1.com.', 'srv2.com.']]
    eq_('srv1.com', dnsq._get_primary_nameserver('tratata.ololo.com'))
