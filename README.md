


# `ptrace` Runtime

As you may well be aware, [`ptrace`](https://www.man7.org/linux/man-pages/man2/ptrace.2.html) can be used to observe and control processes on Linux. This proof of concept uses this functionality to create a kind of client-server runtime.

## Resources

- [`proot-rs`](https://github.com/proot-me/proot-rs), a Rust implementation of a ptrace-based sandbox. Has some very interesting ideas/implementations.
- [`ptrace_syscalls`](https://github.com/ohchase/ptrace_syscalls), a demonstration of the capabilities of using ptrace for injection. Has some more projects that explore some more injection capabilities:
  - [`ptrace-do`](https://github.com/ohchase/ptrace-do), a library for interacting with processes through ptrace.
  - [`plt-rs`](https://github.com/ohchase/plt-rs), an interesting idea for runtime dynamic dispatch with the procedure linkage table. [`plthook`](https://github.com/kubo/plthook) has a good explanation of the idea.
- [`havoc`](https://github.com/trimoq/havoc), a useful reference for a Rust implementation of some basic ptrace functionality.
