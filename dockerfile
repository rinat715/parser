FROM 192.168.1.156:3000/azat715/rust_python3_6:0.1 as builder

WORKDIR /usr/parser/

COPY . .


RUN cargo build