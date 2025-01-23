# Memory Allocator Visualization

This repository contains the codebase for our research on visualizing and analyzing memory allocation mechanisms. The project explores dynamic library hooking and comparative evaluation of memory allocators (`glibc` vs. `ffmalloc`) to provide deeper insights into their behaviors. The results are visualized for clear understanding and reproducibility.

---

## Highlights

- **Dynamic Library Hooking**: Implements hooks for `malloc`, `free`, `realloc`, and other memory allocation functions.
- **Allocator Comparison**: Evaluates `glibc` and `ffmalloc` allocation performance under various workloads.
- **Comprehensive Visualization**: Includes tools for processing logs and generating visual insights into allocation patterns.
- **Open-Source & Reproducible**: Modular design for easy extension and adaptation.

---

## Code Structure

```
├── eval.py             # Script for evaluating memory allocators.
├── analyzer.py         # Script for log preprocessing and visualization.
├── libhook.c           # Implements dynamic hooking of memory allocation functions.
├── pttest.c            # Example program for memory allocation testing.
├── Makefile            # Build script for compiling shared libraries.
├── log/                # Directory for generated logs.
└── README.md           # Project documentation.
```

---

## Prerequisites

### System Requirements

- **Linux OS**: Required for `LD_PRELOAD` support and syscall tracing.
- **Python**: Version 3.6 or higher.
- **GCC**: To compile the shared libraries.
- **strace**: For capturing system calls.

### Python Dependencies

Install the required Python libraries using:

```bash
pip install -r requirements.txt
```

Dependencies include:

- `numpy`
- `matplotlib`

---

## Quick Start

### Step 1: Compile Libraries

Use the provided `Makefile` to compile the necessary shared libraries:

```bash
make
```

### Step 2: Evaluate Memory Allocators

Run the evaluation script to analyze `glibc` and `ffmalloc`:

```bash
python eval.py -l /path/to/libhook.so -f /path/to/libffmalloc.so -r -p "<program_to_trace>"
```

For example:

```bash
python eval.py -l ./libhook.so -f ./libffmalloc.so -r -p "ls"
```

To clean generated logs:

```bash
python eval.py -c
```

### Step 3: Visualize Results

1. Preprocess the logs:
   ```bash
   python analyzer.py -P
   ```
2. Generate visualizations from preprocessed logs:
   ```bash
   python analyzer.py -m ./log/sort.log
   ```

---

## Detailed Workflow

1. **Dynamic Hooking**:
   - Implements custom memory allocation hooks via `libhook.c`.
   - Captures `malloc`, `free`, `realloc`, and related system calls.

2. **Evaluation**:
   - The `eval.py` script uses `strace` and `LD_PRELOAD` to capture logs for both `glibc` and `ffmalloc`.
   - Logs are processed to calculate memory usage metrics.

3. **Visualization**:
   - The `analyzer.py` script visualizes memory allocation patterns for deeper insights.
   - Output includes detailed graphs and memory usage trends.

---

## License

This project is released under the MIT License:

```text
MIT License

Copyright (c) 2025 Ziyu Wang

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Contact

For questions or collaboration inquiries, please contact:

**Ziyu Wang**

---
