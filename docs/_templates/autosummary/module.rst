{% if fullname == "angr" -%}
API Reference
=============
{%- else -%}
{{ fullname | escape | underline }}
{%- endif %}

.. automodule:: {{ fullname }}
{%- if fullname.endswith("_pb2") %}
   :no-index:
{%- endif %}

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
