  {% set firewall = salt['pillar.get']('firewall', {}) %}

  # If flush = true, set policy to ACCEPT and flush all.
  {% set flush = firewall.get('flush', False) %}

  # If testing_mode.enabled = true, it will flush iptables after x seconds.
  {% set testing_mode_enabled = firewall.get('testing_mode:enabled', True) %}
  {% set testing_mode_timer = firewall.get('testing_mode:flush_after', 60)|int %}

  {%- if flush or testing_mode_enabled %}
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

  {%- if testing_mode_enabled %}
      iptables_flush_testing_mode:
        schedule.present:
          - function: state.sls_id
          - job_args:
            - iptables_flush
            - iptables.flush
          # This is a workaround to mimic "now + x seconds", since Salt schedule just supports ISO8601 time format.
          # It generates "now" based on Unix Time, then it add x number of seconds, finally it converts that to ISO8601 time.
          - once: "{{ (None|strftime("%s")|int + testing_mode_timer)|strftime("%Y-%m-%dT%H:%M:%S") }}"
          - once_fmt: "%Y-%m-%dT%H:%M:%S"
          - persist: False
          - order: last
          - require:
            - iptables: iptables_flush
  {%- else %}
      delete_iptables_flush_testing_mode_job:
        schedule.absent:
          - name: iptables_flush_testing_mode
  {%- endif %}
