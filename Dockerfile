FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    build-essential \
    cmake \
    curl \
    # PySide6 / Qt6 runtime dependencies for oxidizer-ui
    libglib2.0-0 \
    libgl1 \
    libegl1 \
    libxkbcommon0 \
    libxkbcommon-x11-0 \
    libdbus-1-3 \
    libfontconfig1 \
    # X11 / xcb libraries required by Qt xcb platform plugin
    libx11-xcb1 \
    libxcb1 \
    libxcb-cursor0 \
    libxcb-glx0 \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-randr0 \
    libxcb-render0 \
    libxcb-render-util0 \
    libxcb-shape0 \
    libxcb-shm0 \
    libxcb-sync1 \
    libxcb-xfixes0 \
    libxcb-xinerama0 \
    libxcb-xkb1 \
    # X11 session/auth libraries
    libsm6 \
    libice6 \
    libx11-6 \
    libxext6 \
    libxrender1 \
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

# Install oxidizer-ui (after angr so its dependency is satisfied)
RUN pip install --no-cache-dir git+https://github.com/sefcom/oxidizer-ui.git

CMD ["bash"]
