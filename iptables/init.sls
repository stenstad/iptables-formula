# Firewall management module
{%- if salt['pillar.get']('firewall:enabled') %}
      include:
        - .install
        - .flush
        - .input 
        - .output 
        - .forward
        - .nat
{%- endif %}

{%- if salt['pillar.get']('firewall:debug') %}
    # Here for debugging
      print_iptables:
        cmd.run:
          - name: "iptables -L -n -v"
{%- endif %}
