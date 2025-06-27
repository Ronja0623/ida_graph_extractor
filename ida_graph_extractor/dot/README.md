# DOT Graph Pipeline Runner

This project provides a simple pipeline to analyze a binary file with IDA Pro, generate a raw call graph in DOT format, create a node mapping, and produce a final reformatted DOT graph with more readable node names.

## Features

- **Automated pipeline** to run IDA scripts and process the resulting graph files.
- Generates:
  - Raw call graph (`callgraph_raw.dot`)
  - Node address-to-name mapping (`node_map.json`)
  - Reformatted final call graph (`callgraph_final.dot`)

## Requirements

- Python 3.7+
- IDA Pro (with command-line execution capabilities)
- Required IDA Python scripts:
  - `scripts/generate_dot.py`
  - `scripts/generate_addr_mapping.py`

## Usage

Run the pipeline script from the command line:

```bash
python your_script.py --binary /path/to/binary -o /path/to/output_dir
```

### Arguments

- `--binary` (required): Path to the binary file to analyze with IDA.
- `-o` / `--output` (optional): Output directory for the generated files. Default is `./output`.

## How It Works

1. **Generate Raw DOT**: Runs `generate_dot.py` with IDA to extract the raw call graph.
2. **Generate Node Mapping**: Runs `generate_addr_mapping.py` with IDA to map node addresses to human-readable names.
3. **Reformat DOT**: Uses `reformat_dot` to replace node addresses in the raw DOT file with readable names.

If any step fails (e.g., required output files are missing), the pipeline exits with an error.

## Logging

Progress and errors are logged to the console for easy debugging.

## Project Structure

```
.
├── scripts/
│   ├── generate_dot.py
│   ├── generate_addr_mapping.py
│   └── reformat_dot.py
├── utils/
├── your_script.py
└── output/
    ├── callgraph_raw.dot
    ├── node_map.json
    └── callgraph_final.dot
```

## License

Specify your license here, e.g., MIT.

## Notes

- Ensure that IDA Pro is installed and accessible via command line.
- The `run_ida_script` utility should correctly handle calling IDA with the necessary parameters.