# 100 Days of Yara in 2024: Day 17

## The Data Layout
Again, we are going to use our trusty [`loader.h`](https://opensource.apple.com/source/xnu/xnu-4570.1.46/EXTERNAL_HEADERS/mach-o/loader.h.auto.html) file for Mach-O binaries. It indentifiers 
```c

```

I mapped this data out into the following structures in Rust:
```rust
```
## Parsing the Data

### Handling Function
The handling function involves some error checking, invoking the parsing function, and setting the relevant details in the protobuf representation.
```rust
```

### Parsing Function
The parsing function will be called by the handling function above. We have two parsing functions for a struct:

```rust
```

## End Result
We can now see the relevant data being parsed in our goldenfiles and testing from this snippet below:

```
[...]

    build_version:
        platform: 1
        minos: "10.15.0"
        sdk: "14.2.0"
        ntools: 1
    build_tools:
      - tool: 50
        version: 32

[...]
```

## Finished Work

I submitted a PR to YARA-X  here: [#73](https://github.com/VirusTotal/yara-x/pull/73) :)