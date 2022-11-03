# iode-snort

This project contains the system part of the **iodé blocker**, intended to be used as part of the [iodéOS](https://gitlab.com/iode/os/public/) Android-based operating system. The user interface can be found [here](https://gitlab.com/iode/os/public/blocker/iode).

## Design principles

This sofware has been designed with several principles in mind:

* *Speed*. It is written in C++, multi-threaded, with appropriate data structures to lower as much as possible the algorithmic complexity. These data structures have also been thought to entirely contain all the blocker data into memory while remaining of reasonable size. Some nowadays unusual design choices have also been made, like the use of some global variables to avoid indirection levels and lighten function calls.
* *Reliability*. It follows as much as possible the [RAII principles](https://en.wikipedia.org/wiki/Resource_acquisition_is_initialization) and heavily relies on the C++ Standard Template Library.
* *Independence*. It is as much as possible independent of the Android system itself, and the use of non C/C++ standard libraries has been limited to the strict minimum. It is also independent of any user interface, providing a simple communcation API through a unix socket.
* *Conciseness*. This code is designed to do one thing, and do it as best as possible. No complex design patterns or unnecessary abstractions, leading to a relatively small code base.

## Contributing

Contributions are welcome, provided that they follow our design principles. We plan to extend this page in the future to give more technical details, and *maybe* comment a bit the code...

The code must be formatted with the [clang-format](https://clang.llvm.org/docs/ClangFormat.html) tool and the given style file.

## License

This software is released under the terms of the [GNU AGPLv3](https://gitlab.com/iode/os/public/blocker/iode-snort/-/raw/staging/LICENSE).