  # if no input section defined, try legacy pillar without input/output
  # sections and input services/whitelist are directly under firewall
  {% set firewall = salt['pillar.get']('firewall', {}) %}
  {% set input = firewall.get( 'input' , firewall ) %}
  {% set icmp = input.get('icmp', False) %}
  {% set strict_mode = input.get('strict', False ) %}
  {% set global_block_nomatch = input.get('block_nomatch', False) %}

  # Input Strict Mode
  # when Enabled, add rules for localhost/established connections
  #   at the top and set policy to reject
  # when Disabled, remove rules for localhost/established connections
  #   and set policy to allow

  {% if strict_mode %}
    {% set action = 'insert' %}
    {% set policy = 'DROP' %}
    {% set strict_position = '- position: 1' %}
    {% set white_position  = '- position: 3' %}
  {%- else %}
    {% set action = 'delete' %}
    {% set policy = 'ACCEPT' %}
    {% set strict_position = '' %}
    {% set white_position = '- position: 1' %}
  {%- endif %}

      # Rule for related/established sessions
      iptables_input_allow_established:
        iptables.{{ action }}:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True
          {{ strict_position }}

      iptables_input_allow_established_v6:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True
          {{ strict_position }}

      # Rule for localhost communications
      iptables_input_allow_localhost:
        iptables.{{ action }}:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: 127.0.0.1
          - save: True
          {{ strict_position }}

      iptables_input_allow_localhost_v6:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: 'ipv6'
          - source: '::1/128'
          - destination: '::1/128'
          - save: True
          {{ strict_position }}

  # Set the input policy to deny everything not explicitly allowed
      iptables_input_enable_reject_policy:
        iptables.set_policy:
          - table: filter
          - chain: INPUT
          - policy: {{ policy }}
          - require:
            - iptables: iptables_input_allow_localhost
            - iptables: iptables_input_allow_established

      iptables_input_enable_reject_policy_v6:
        iptables.set_policy:
          - table: filter
          - chain: INPUT
          - policy: {{ policy }}
          - family: 'ipv6'
          - require:
            - iptables: iptables_input_allow_localhost_v6
            - iptables: iptables_input_allow_established_v6

      # We need to allow IPv6 locally
      iptables_input_enable_icmpv6_router_advertisement:
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

      iptables_input_enable_icmpv6_neighbor_solicitation:
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

      iptables_input_enable_icmpv6_neighbor_advertisement:
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

      iptables_input_enable_icmpv6_redirect:
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

  # Whitelisting

  # Insert whitelist IPs and interfaces.
  {%- set whitelist = input.get( 'whitelist', {}) %}
  {%- for ip in whitelist.get('ips_allow', {}) %}
      iptables_input_whitelist_allow_{{ ip }}:
        iptables.insert:
           - table: filter
           - chain: INPUT
           - jump: ACCEPT
           - source: {{ ip }}
           - save: True
           {{ white_position }}
  {%- endfor %}

  {%- for ip in whitelist.get('ip6s_allow', {}) %}
      iptables_input_whitelist_allow_{{ ip }}:
        iptables.insert:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: {{ ip }}
          - family: 'ipv6'
          - save: True
          {{ white_position }}
  {%- endfor %}

  {%- for interface in whitelist.get('interfaces', {}) %}
      iptables_input_whitelist_allow_{{ interface }}:
        iptables.insert:
           - table: filter
           - chain: INPUT
           - jump: ACCEPT
           - i: {{ interface }}
           - save: True
           {{ white_position }}
  {%- endfor %}

  # Remove whitelist IPs and interfaces.
  {%- for ip in whitelist.get('ips_remove', {}) %}
      iptables_input_whitelist_allow_{{ ip }}:
        iptables.delete:
           - table: filter
           - chain: INPUT
           - jump: ACCEPT
           - source: {{ ip }}
           - save: True
  {%- endfor %}

  {%- for network in whitelist.get('ip6s_remove',{} ) %}
      iptables_input_whitelist_allow_{{ ip }}:
        iptables.delete:
           - table: filter
           - chain: INPUT
           - jump: ACCEPT
           - source: {{ ip }}
           - family: 'ipv6'
           - save: True
  {%- endfor %}

  {%- for interface in whitelist.get('interfaces_remove', {}) %}
      iptables_input_whitelist_allow_{{ interface }}:
        iptables.delete:
           - table: filter
           - chain: INPUT
           - jump: ACCEPT
           - i: {{ interface }}
           - save: True
  {%- endfor %}

  {%- if icmp %}
  # Allow ICMP inbound

      iptables_input_enable_icmp_echo_request:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - proto: icmp
          - icmp-type: echo-request
          - save: True

      iptables_input_enable_icmp_echo_reply:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - proto: icmp
          - icmp-type: echo-request
          - save: True

      iptables_input_enable_icmpv6_destination_unreachable:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: destination-unreachable
          - save: True

      iptables_input_enable_icmpv6_packet_too_big:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: packet-too-big
          - save: True

      iptables_input_enable_icmpv6_time_exceeded:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: time-exceeded
          - save: True

      iptables_input_enable_icmpv6_parameter_problem:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: parameter-problem
          - save: True

      iptables_input_enable_icmpv6_echo_request:
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

      iptables_input_enable_icmpv6_echo_reply:
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

  # Rules for services
  {%- for service_name, service_details in input.get('services', {}).items() %}
    {% set block_nomatch = service_details.get('block_nomatch', False) %}
    {% set interfaces = service_details.get('interfaces','') %}
    {% set protos = service_details.get('protos',['tcp']) %}

    # Check if rule is marked for removal
    {%- if service_details.get('remove') %}
      {% set action = 'delete' %}
    {%- else %}
      {% set action = 'append' %}
    {%- endif %}

    #Allow rules for ips/subnets
    {%- for ip in service_details.get('ips_allow',{}) %}
      {%- if interfaces == '' %}
        {%- for proto in protos %}
      iptables_input_{{service_name}}_allow_{{ip}}:
        iptables.{{ action }}:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: {{ ip }}
          - dport: {{ service_name }}
          - proto: tcp
          - save: True
        {%- endfor %}
      {%- else %}
        {%- for interface in interfaces %}
          {%- for proto in protos %}
      iptables_input_{{service_name}}_allow_{{ip}}:
        iptables.{{ action }}:
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
      iptables_input_{{service_name}}_allow_{{ip}}_{{proto}}:
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
      iptables_input_{{service_name}}_allow_{{ip}}_{{proto}}_{{interface}}:
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

    # Remove any IPs in ips_remove
    {%- for ip in service_details.get('ips_remove',{}) %}
      {%- if interfaces == '' %}
        {%- for proto in protos %}
      iptables_input_{{service_name}}_allow_{{ip}}:
        iptables.delete:
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
      iptables_input_{{service_name}}_allow_{{ip}}:
        iptables.delete:
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

    # Remove any IPs in ip6s_remove
    {%- for ip in service_details.get('ip6s_remove',{}) %}
      {%- if interfaces == '' %}
        {%- for proto in protos %}
      iptables_input_{{service_name}}_allow_{{ip}}:
        iptables.delete:
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
      iptables_input_{{service_name}}_allow_{{ip}}:
        iptables.delete:
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

    # no_match rules
    # Only add no_match rule when strict is false and a no_match is true and the service is not marked remove
    {%- if not strict_mode and ( global_block_nomatch or block_nomatch ) and not service_details.get('remove') %}
      {% set action = 'append' %}
    {%- else %}
      {% set action = 'delete' %}
    {%- endif %}

    # no_match blocking rule
    {%- for proto in protos %}

    iptables_forward_{{service_name}}_deny_other:
      iptables.{{ action }}:
        - table: filter
        - chain: INPUT
        - jump: REJECT
        - dport: {{ service_name }}
        - proto: {{ proto }}
        - save: True

    iptables_forward_{{service_name}}_deny_other_v6:
      iptables.{{ action }}:
        - table: filter
        - chain: INPUT
        - jump: REJECT
        - dport: {{ service_name }}
        - proto: {{ proto }}
        - family: 'ipv6'
        - save: True

    {%- endfor %}

  {%- endfor %}
