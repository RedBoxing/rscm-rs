# noexes-rs
noexes-rs is a client for [Noexes](https://github.com/mdbell/Noexes) written in Rust.

## Features
- [x] Attach to a running process (including current process)
- [x] Read memory
- [x] Write memory
- [x] Display asm instructions when reading memory
- [x] Pause/resume process
- [x] Get process list
- [x] Get Status
- [x] Query memory regions
- [ ] Search 
- [ ] Set breakpoints
- [ ] View what accesses/writes to a memory address

## Commands

### Connect
```
connect <ip>:<port>
```
Connects to a Noexes server at the given ip and port. (Default port is 7331)

### Disconnect
```
disconnect
```
Disconnects from the current server.

### Exit
```
exit
```
Exits the program.

### Status
```
status
```
Gets the status of the current server.

### Attach
```
attach <pid>
```
Attaches to a process with the given pid.

### Attach Current
```
attach_current
```
Attaches to the current process.

### Get PIDs
```
get_pids
```
Gets a list of all running process ids.

### Get Current PID
```
get_current_pid
```
Gets the pid of the current process.

### Get Current TitleID
```
get_current_title_id
```
Gets the title id of the current process.

### Get Attached PID
```
get_attached_pid
```
Gets the pid of the attached process.

### Pause
```
pause
```
Pauses the attached process.

### Resume
```
resume
```
Resumes the attached process.

### Query Memory
```
query <address>
```
Queries the memory region at the given address.

### Read Memory
```
peek <address> <size>
```
Reads the given number of bytes from the given address.

### Write Memory
```
poke <address> <size> <bytes>
```
Writes the given bytes to the given address.