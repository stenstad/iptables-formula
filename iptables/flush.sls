  {% set firewall = salt['pillar.get']('firewall', {}) %}

  # if flush = true, set policy to ACCEPT and flush all 
  {% set flush = firewall.get('flush', False ) %}

  {%- if flush %}
  # IPv6 is missing!
      iptables_input_policy_accept:
        iptables.set_policy:
          - table: filter
          - chain: INPUT
          - policy: ACCEPT

      iptables_output_policy_accept:
        iptables.set_policy:
          - table: filter
          - chain: OUTPUT
          - policy: ACCEPT

      iptables_forward_policy_accept:
        iptables.set_policy:
          - table: filter
          - chain: FORWARD
          - policy: ACCEPT

      iptables_flush:
        iptables.flush:
          - table: filter
          - require:
            - iptables: iptables_input_policy_accept
            - iptables: iptables_output_policy_accept
            - iptables: iptables_forward_policy_accept
  {%- endif %}
