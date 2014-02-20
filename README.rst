dnsq
====

DNS Query Tool

Usage
-----

.. code-block:: py

   >>> import dnsq
   >>> dnsq.query_dns('www.example.com', 'a')
   ['93.184.216.119']

.. code-block:: py

   >>> import dnsq
   >>> dnsq.mx_hosts_for('example.com')
   ['example.com']
