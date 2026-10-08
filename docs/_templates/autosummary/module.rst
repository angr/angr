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
{#- angr.unicornlib is the native library that angr loads with ctypes, not a Python module. #}
{%- set modules = modules | reject("in", ["unicornlib"] if fullname == "angr" else []) | list %}
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
