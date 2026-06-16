{% if fullname == "angr" -%}
API Reference
=============
{%- else -%}
{{ fullname | escape | underline }}
{%- endif %}

.. automodule:: {{ fullname }}

{% block modules %}
{% if modules %}
.. rubric:: Submodules

.. autosummary::
   :toctree:
   :recursive:
{% for item in modules %}
   {{ item }}
{%- endfor %}
{% endif %}
{% endblock %}
