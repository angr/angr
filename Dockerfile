FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    cmake \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (needed by setuptools-rust)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Install build tools
RUN pip install --no-cache-dir setuptools setuptools-rust

# Install Rust demangler dependency
RUN pip install --no-cache-dir rust-demangler==1.0

# Install pinned angr dependencies
RUN pip install --no-cache-dir \
    git+https://github.com/angr/archinfo.git@84ad167543028b32e170d3659650707b3866185c \
    git+https://github.com/angr/claripy.git@8b890bb13fe743bfdbaae119062631db4f10047b \
    git+https://github.com/angr/pyvex.git@3f92fece7147e91cea401e14a3936f20860a402e \
    git+https://github.com/angr/cle.git@ce3333d0e1e72936fdbb75eefd70299ead4fb998

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir --no-build-isolation -e .

CMD ["bash"]
