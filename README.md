# libcicero
An implementation of ICE Lite protocol, based on libnice. The aim of the project is to create pure C library, which can be easily integrated into applications. 

TODO:
  + Support only udp, extension for tcp is needed.
  + Add support for reflexive candidate via stun requests.
  + It currently depends on libevent, but in the future select/epoll/kqueue should be added.

