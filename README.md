# Socket Network Programming Examples

A comprehensive collection of Python socket programming examples demonstrating various networking concepts, from basic client-server communication to advanced protocol implementations.

## 📁 Repository Structure

### Basic Examples
- **`base/`** - Fundamental client-server echo implementation
- **`echo/`** - Simple echo server examples
- **`echo2/`** - Alternative echo server implementation

### Communication Examples
- **`talk_one_to_one/`** - Interactive bidirectional communication
- **`conversation/`** - Advanced conversation system with custom socket wrapper
- **`base_multi_clients/`** - Multi-client server handling

### Application Examples
- **`ask_weather/`** - Weather query service with local data
- **`ask_weather_from_internet/`** - Weather service with external API integration

### Advanced Implementations
- **`conversation_protocol/`** - Custom protocol implementation with structured commands
- **`original_python_socket/`** - Visual Studio project templates

## 🚀 Getting Started

### Prerequisites
- Python 3.x
- Network connectivity for internet-based examples

### Basic Usage

1. **Simple Echo Server**
   ```bash
   # Terminal 1 - Start server
   cd base
   python base_server.py
   
   # Terminal 2 - Start client
   python base_client.py
   ```

2. **Interactive Chat**
   ```bash
   # Terminal 1
   cd talk_one_to_one
   python talk_server.py
   
   # Terminal 2
   python talk_client.py
   ```

## 📋 Examples Overview

### 1. Base Echo System (`base/`)
**Files:** `base_server.py`, `base_client.py`, `base_constant.py`

Basic TCP client-server implementation that echoes received messages back to the client.

**Features:**
- Single client connection
- Message echoing
- Configurable server settings

### 2. Weather Query Service (`ask_weather/`)
**Files:** `ask_weather_server.py`, `ask_weather_client.py`, `ask_weather_constant.py`

A practical example demonstrating data lookup services over TCP.

**Features:**
- Date-based weather queries
- Predefined weather data
- Error handling for unknown dates

### 3. Internet Weather Service (`ask_weather_from_internet/`)
**Files:** `weather_server.py`, `weather_client.py`, `weather_lib.py`, `base_constant.py`

Advanced weather service that fetches real-time data from external APIs.

**Features:**
- External API integration
- Real-time weather data
- Modular library design

### 4. Conversation System (`conversation/`)
**Files:** `conversation_client.py`, `conversation.py`, `my_socket/Socket.py`, `my_socket/ServerSocket.py`

Object-oriented socket wrapper with enhanced functionality.

**Features:**
- Custom Socket class
- Simplified API
- Enhanced error handling

### 5. Protocol Implementation (`conversation_protocol/`)
**Files:** Multiple protocol definition and parser files

Sophisticated protocol implementation with structured command system.

**Features:**
- Custom protocol definition
- Command-based communication
- Protocol parsing and validation
- Support for multiple commands: CALL, ANSW, REJT, REQU, RESP, RELS, RELD, ERRR

### 6. Multi-Client Support (`base_multi_clients/`)
**Files:** `base_server.py`, `base_client.py`, `base_constant.py`

Server implementation capable of handling multiple concurrent clients.

**Features:**
- Concurrent client handling
- Scalable architecture
- Resource management

### 7. Interactive Communication (`talk_one_to_one/`)
**Files:** `talk_server.py`, `talk_client.py`, `talk2_server.py`, `talk2_client.py`, `thread_try.py`

Bidirectional communication examples with threading support.

**Features:**
- Real-time messaging
- Threading implementation
- Interactive user interface

## 🔧 Configuration

Most examples use configurable constants defined in `*_constant.py` files:

```python
SERVER_IP_ADDRESS = '192.168.0.110'
SERVER_PORT = 56789
BUFFER_SIZE = 1024
```

Update these values according to your network setup.

## 🏗️ Architecture Patterns

### Basic Client-Server Pattern
```
Client ←→ Server
```

### Multi-Client Pattern
```
Client 1 ←→
Client 2 ←→ Server
Client N ←→
```

### Protocol-Based Communication
```
Client ←→ [Protocol Layer] ←→ Server
```

## 📚 Learning Path

1. **Start with `base/`** - Understand fundamental socket concepts
2. **Explore `echo/`** - Learn about message handling
3. **Try `talk_one_to_one/`** - Experience bidirectional communication
4. **Study `ask_weather/`** - See practical application development
5. **Examine `conversation_protocol/`** - Understand advanced protocol design
6. **Review `base_multi_clients/`** - Learn concurrent client handling

## 🛠️ Development Environment

The repository includes Visual Studio project files (`.pyproj`, `.sln`) for Windows development:
- `conversation/conversation.pyproj`
- `original_python_socket/PythonTcpClient/`
- `original_python_socket/PythonTcpServer/`

## 🔍 Key Concepts Demonstrated

- **TCP Socket Programming** - Client-server communication
- **Protocol Design** - Custom communication protocols
- **Concurrent Programming** - Multi-client handling
- **Error Handling** - Network error management
- **API Integration** - External service consumption
- **Object-Oriented Design** - Socket wrapper classes
- **Threading** - Concurrent execution patterns

## 📝 Notes

- Default server IP is set to `192.168.0.110` - update for your network
- Buffer size is typically set to 1024 bytes
- Most examples support graceful shutdown with 'exit' command
- Some examples include Visual Studio project files for Windows development

## 🤝 Contributing

This repository serves as a learning resource for socket programming concepts. Each example is self-contained and demonstrates specific networking patterns.

## 📄 License

Educational use - Socket programming examples and demonstrations.