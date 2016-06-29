# Firewall management module
{%- if salt['pillar.get']('firewall:enabled') %}
  {% set firewall = salt['pillar.get']('firewall', {}) %}
  {% set install = firewall.get('install', False) %}
  {% set strict_mode = firewall.get('strict', False) %}
  {% set global_block_nomatch = firewall.get('block_nomatch', False) %}
  {% set icmp = firewall.get('icmp', False) %}
  {% set packages = salt['grains.filter_by']({
    'Debian': ['iptables', 'iptables-persistent'],
    'RedHat': ['iptables'],
    'default': 'Debian'}) %}

    {%- if install %}
      # Install required packages for firewalling      
      iptables_packages:
        pkg.installed:
          - pkgs:
            {%- for pkg in packages %}
            - {{pkg}}
            {%- endfor %}
    {%- endif %}

    {%- if strict_mode %}
      # If the firewall is set to strict mode, we'll need to allow some 
      # that always need access to anything
      iptables_allow_localhost:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: 127.0.0.1
          - save: True

      iptables_allow_localhost_v6:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - source: '::1/128'
          - destination: '::1/128'
          - save: True

      # Allow related/established sessions
      iptables_allow_established:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True            

      iptables_allow_established_v6:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True

      # Set the policy to deny everything unless defined
      enable_reject_policy:
        iptables.set_policy:
          - table: filter
          - chain: INPUT
          - policy: DROP
          - require:
            - iptables: iptables_allow_localhost
            - iptables: iptables_allow_established

      enable_reject_policy_v6:
        iptables.set_policy:
          - table: filter
          - chain: INPUT
          - policy: DROP
          - family: ipv6
          - require:
            - iptables: iptables_allow_localhost_v6
            - iptables: iptables_allow_established_v6

      # We need to allow IPv6 locally
      enable_icmpv6_router_advertisement:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: router-advertisement
          - match: hl
          - hl-eq: 255
          - save: True

      enable_icmpv6_neighbor_solicitation:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: neighbor-solicitation
          - match: hl
          - hl-eq: 255
          - save: True

      enable_icmpv6_neighbor_advertisement:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: neighbor-advertisement
          - match: hl
          - hl-eq: 255
          - save: True

      enable_icmpv6_redirect:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: redirect
          - match: hl
          - hl-eq: 255
          - save: True

    {%- endif %}

    {%- if icmp %}
    # Allow ICMP inbound

      enable_icmp_echo_request:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - proto: icmp
          - icmp-type: echo-request
          - save: True

      enable_icmp_echo_reply:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - proto: icmp
          - icmp-type: echo-request
          - save: True
    
      enable_icmpv6_destination_unreachable:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: destination-unreachable
          - save: True

      enable_icmpv6_packet_too_big:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: packet-too-big
          - save: True

      enable_icmpv6_time_exceeded:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: time-exceeded
          - save: True

      enable_icmpv6_parameter_problem:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: parameter-problem
          - save: True

      enable_icmpv6_echo_request:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - match: limit
          - limit: 900/min
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: echo-request
          - save: True

      enable_icmpv6_echo_reply:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - match: limit
          - limit: 900/min
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: echo-reply
          - save: True
    {% endif %}

  # Generate ipsets for all services that we have information about
  {%- for service_name, service_details in firewall.get('services', {}).items() %}  
    {% set block_nomatch = service_details.get('block_nomatch', False) %}
    {% set interfaces = service_details.get('interfaces','') %}
    {% set protos = service_details.get('protos',['tcp']) %}

    # Allow rules for ips/subnets
    {%- for ip in service_details.get('ips_allow', []) %}
      {%- if interfaces == '' %}
        {%- for proto in protos %}
      iptables_{{service_name}}_allow_{{ip}}_{{proto}}:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: {{ ip }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
        {%- endfor %}
      {%- else %}
        {%- for interface in interfaces %}
          {%- for proto in protos %}
      iptables_{{service_name}}_allow_{{ip}}_{{proto}}_{{interface}}:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - i: {{ interface }}
          - source: {{ ip }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
          {%- endfor %}
        {%- endfor %}
      {%- endif %}
    {%- endfor %}

    {%- for ip in service_details.get('ip6s_allow', []) %}
      {%- if interfaces == '' %}
        {%- for proto in protos %}
      iptables_{{service_name}}_allow_{{ip}}_{{proto}}:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: {{ ip }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - family: 'ipv6'
          - save: True
        {%- endfor %}
      {%- else %}
        {%- for interface in interfaces %}
          {%- for proto in protos %}
      iptables_{{service_name}}_allow_{{ip}}_{{proto}}_{{interface}}:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - i: {{ interface }}
          - source: {{ ip }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - family: 'ipv6'
          - save: True
          {%- endfor %}
        {%- endfor %}
      {%- endif %}
    {%- endfor %}

    {%- if not strict_mode and global_block_nomatch or block_nomatch %}
      # If strict mode is disabled we may want to block anything else
      {%- if interfaces == '' %}
        {%- for proto in protos %}
      iptables_{{service_name}}_deny_other_{{proto}}:
        iptables.append:
          - position: last
          - table: filter
          - chain: INPUT
          - jump: REJECT
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True

      iptables_{{service_name}}_deny_other_{{proto}}_v6:
        iptables.append:
          - position: last
          - table: filter
          - chain: INPUT
          - jump: REJECT
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - family: 'ipv6'
          - save: True
        {%- endfor %}
      {%- else %}
        {%- for interface in interfaces %}
          {%- for proto in protos %}
      iptables_{{service_name}}_deny_other_{{proto}}_{{interface}}:
        iptables.append:
          - position: last
          - table: filter
          - chain: INPUT
          - jump: REJECT
          - i: {{ interface }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True

      iptables_{{service_name}}_deny_other_{{proto}}_v6_{{interface}}:
        iptables.append:
          - position: last
          - table: filter
          - chain: INPUT
          - jump: REJECT
          - i: {{ interface }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - family: 'ipv6'
          - save: True
          {%- endfor %}
        {%- endfor %}
      {%- endif %}

    {%- endif %}    

  {%- endfor %}

  # Generate rules for NAT
  {%- for service_name, service_details in firewall.get('nat', {}).items() %}  
    {%- for ip_s, ip_ds in service_details.get('rules', {}).items() %}
      {%- for ip_d in ip_ds %}
      iptables_{{service_name}}_allow_{{ip_s}}_{{ip_d}}:
        iptables.append:
          - table: nat 
          - chain: POSTROUTING 
          - jump: MASQUERADE
          - o: {{ service_name }} 
          - source: {{ ip_s }}
          - destination: {{ip_d}}
          - save: True
      {%- endfor %}
    {%- endfor %}
  {%- endfor %}

  # Generate rules for whitelisting IP classes
  {%- for service_name, service_details in firewall.get('whitelist', {}).items() %}
    {%- for ip in service_details.get('ips_allow', []) %}
      iptables_{{service_name}}_allow_{{ip}}:
        iptables.append:
           - table: filter
           - chain: INPUT
           - jump: ACCEPT
           - source: {{ ip }}
           - save: True
    {%- endfor %}
  {%- endfor %}

{%- endif %}
