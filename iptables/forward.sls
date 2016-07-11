  {% set firewall = salt['pillar.get']('firewall', {}) %}
  {% set forward = firewall.get( 'forward' , {} ) %}
  {% set icmp = forward.get('icmp', False) %}
  {% set strict_mode = forward.get('strict', False ) %}
  {% set global_block_nomatch = forward.get('block_nomatch', False ) %}

  # Forward Strict Mode
  # when Enabled, add rules for established connections 
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
      iptables_forward_allow_established:
        iptables.{{ action }}:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True
          {{ strict_position }}

      iptables_forward_allow_established_v6:
        iptables.append:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - family: ipv6
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True
          {{ strict_position }}

  # Set the FORWARD policy to deny everything not explicitly allowed
      iptables_forward_enable_reject_policy:
        iptables.set_policy:
          - table: filter
          - chain: FORWARD
          - policy: {{ policy }}
          - require:
            - iptables: iptables_forward_allow_established

      iptables_forward_enable_reject_policy_v6:
        iptables.set_policy:
          - table: filter
          - chain: FORWARD
          - policy: {{ policy }}
          - family: 'ipv6'
          - require:
            - iptables: iptables_forward_allow_established_v6

  # Whitelisting

  # Insert whitelist IPs and interfaces.
  {%- set whitelist = forward.get( 'whitelist', {}) %}
  {%- for ip in whitelist.get('ips_allow', {}) %}
      iptables_forward_whitelist_allow_{{ ip }}:
        iptables.insert:
           - table: filter
           - chain: FORWARD
           - jump: ACCEPT
           - source: {{ ip }}
           - save: True
           {{ white_position }}
  {%- endfor %}

  {%- for ip in whitelist.get('ip6s_allow', {}) %}
      iptables_forward_whitelist_allow_{{ ip }}:
        iptables.insert:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - source: {{ ip }}
          - family: 'ipv6'
          - save: True
          {{ white_position }}
  {%- endfor %}

  {%- for interface in whitelist.get('interfaces', {}) %}
      iptables_forward_whitelist_allow_{{ interface }}:
        iptables.insert:
           - table: filter
           - chain: FORWARD
           - jump: ACCEPT
           - i: {{ interface }}
           - save: True
           {{ white_position }}
  {%- endfor %}

  # Remove whitelist IPs and interfaces.
  {%- for ip in whitelist.get('ips_remove', {}) %}
      iptables_forward_whitelist_allow_{{ ip }}:
        iptables.delete:
           - table: filter
           - chain: FORWARD
           - jump: ACCEPT
           - source: {{ ip }}
           - save: True
  {%- endfor %}

  {%- for network in whitelist.get('ip6s_remove',{} ) %}
      iptables_forward_whitelist_allow_{{ ip }}:
        iptables.delete:
           - table: filter
           - chain: FORWARD
           - jump: ACCEPT
           - source: {{ ip }}
           - family: 'ipv6'
           - save: True
  {%- endfor %}

  {%- for interface in whitelist.get('interfaces_remove', {}) %}
      iptables_forward_whitelist_allow_{{ interface }}:
        iptables.delete:
           - table: filter
           - chain: FORWARD
           - jump: ACCEPT
           - i: {{ interface }}
           - save: True
  {%- endfor %}

  {%- if icmp %}
    # Allow ICMP forwarding

      iptables_forward_enable_icmp_echo_request:
        iptables.append:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - proto: icmp
          - icmp-type: echo-request
          - save: True

      iptables_forward_enable_icmp_echo_reply:
        iptables.append:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - proto: icmp
          - icmp-type: echo-request
          - save: True

      iptables_forward_enable_icmpv6_destination_unreachable:
        iptables.append:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: destination-unreachable
          - save: True

      iptables_forward_enable_icmpv6_packet_too_big:
        iptables.append:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: packet-too-big
          - save: True

      iptables_forward_enable_icmpv6_time_exceeded:
        iptables.append:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: time-exceeded
          - save: True

      iptables_forward_enable_icmpv6_parameter_problem:
        iptables.append:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: parameter-problem
          - save: True

      iptables_forward_enable_icmpv6_echo_request:
        iptables.append:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - match: limit
          - limit: 900/min
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: echo-request
          - save: True

      iptables_forward_enable_icmpv6_echo_reply:
        iptables.append:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - match: limit
          - limit: 900/min
          - family: ipv6
          - proto: icmpv6
          - icmpv6-type: echo-reply
          - save: True
  {% endif %}

  # Rules for services
  {%- for service_name, service_details in forward.get('services', {}).items() %}
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
      iptables_forward_{{service_name}}_{{proto}}_allow_{{ip}}:
        iptables.{{ action }}:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - destination: {{ ip }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
        {%- endfor %}
      {%- else %}
        {%- for interface in interfaces %}
          {%- for proto in protos %}
      iptables_forward_{{service_name}}_{{proto}}_allow_{{ip}}:
        iptables.{{ action }}:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - i: {{ interface }}
          - destination: {{ ip }}
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
      iptables_forward_{{service_name}}_{{proto}}_allow_{{ip}}:
        iptables.append:
          - table: filter
          - chain: FORWARD
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
      iptables_forward_{{service_name}}_{{proto}}_allow_{{ip}}_{{interface}}:
        iptables.append:
          - table: filter
          - chain: FORWARD
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
      iptables_forward_{{service_name}}_{{proto}}_allow_{{ip}}:
        iptables.delete:
          - table: filter
          - chain: FORWARD
          - jump: ACCEPT
          - source: {{ ip }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
        {%- endfor %}
      {%- else %}
        {%- for interface in interfaces %}
          {%- for proto in protos %}
      iptables_forward_{{service_name}}_{{proto}}_allow_{{ip}}:
        iptables.delete:
          - table: filter
          - chain: FORWARD
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
      iptables_forward_{{service_name}}_{{proto}}_allow_{{ip}}:
        iptables.delete:
          - table: filter
          - chain: FORWARD
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
      iptables_forward_{{service_name}}_{{proto}}_allow_{{ip}}:
        iptables.delete:
          - table: filter
          - chain: FORWARD
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
      iptables_forward_{{service_name}}_{{proto}}_deny_other:
        iptables.{{ action }}:
          - table: filter
          - chain: FORWARD
          - jump: REJECT
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True

      iptables_forward_{{service_name}}_{{proto}}_deny_other_v6:
        iptables.{{ action }}:
          - table: filter
          - chain: FORWARD
          - jump: REJECT
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - family: 'ipv6'
          - save: True
    {%- endfor %}

  {%- endfor %}
