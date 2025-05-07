


# `ptrace` Runtime

As you may well be aware, [`ptrace`](https://www.man7.org/linux/man-pages/man2/ptrace.2.html) can be used to observe and control processes on Linux. With the help of [`seccomp`](https://www.man7.org/linux/man-pages/man2/seccomp.2.html), this proof of concept uses this functionality to create a kind of client-server runtime.

## How It Works

When you run a program through this runtime, the runtime process calls [`fork`](https://www.man7.org/linux/man-pages/man2/fork.2.html) on itself, splitting

For the child process, the following occurs:

1. First, it performs a `PTRACE_TRACEME` request.
2. Then it creates a [`bpf`](https://www.man7.org/linux/man-pages/man2/bpf.2.html) (Berkeley Packet Filter) program that defines the set of "top-level" rules for the program's syscalls.
3. The child then ensures that the `no_new_privs` bit is set to make sure that the `seccomp` operation performed in the next step succeeds.
4. It will use the BPF program create in step 2 to apply a `seccomp` filter to itself.
5. Finally, the child calls [`execve`](https://www.man7.org/linux/man-pages/man2/execve.2.html) on the program to start it in the child's place.

And for the parent process, the following occurs:

1. First, the parent waits for the child process to finish its startup process (see above).
2. Once the child is ready, the parent then sets up its `ptrace` options to handle the `seccomp` traps it will receive. This is primarily done by setting `PTRACE_O_TRACESECCOMP`.
3. Finally, the parent enters its event loop in which it:
    1. Waits for the child to perform a syscall, exit, etc.
    2. Handles that action in whatever way it sees fit. Maybe by stopping the syscall entirely, modifying the child's registers, or whatever creative idea I think would be cool.

## Resources

- [`proot-rs`](https://github.com/proot-me/proot-rs), a Rust implementation of a ptrace-based sandbox. Has some very interesting ideas/implementations.
- [`ptrace_syscalls`](https://github.com/ohchase/ptrace_syscalls), a demonstration of the capabilities of using ptrace for injection. Has some more projects that explore some more injection capabilities:
  - [`ptrace-do`](https://github.com/ohchase/ptrace-do), a library for interacting with processes through ptrace.
  - [`plt-rs`](https://github.com/ohchase/plt-rs), an interesting idea for runtime dynamic dispatch with the procedure linkage table. [`plthook`](https://github.com/kubo/plthook) has a good explanation of the idea.
- [`havoc`](https://github.com/trimoq/havoc), a useful reference for a Rust implementation of some basic ptrace functionality.
