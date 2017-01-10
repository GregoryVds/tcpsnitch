### tcpsnitch\_analyzer

## Usage

Analysis scripts for tcpsnitch JSON traces. Accepts a single or multiple traces as argument.

The first important option is `-a`, which indicates the type of analysis to perform on the traces. It can compute 3 types:
- Descriptive statistics: use `-a desc` or `-a d`. Compute a serie of descriptive statistics for values at a given node in the JSON trace. Valid for numerical values only.
- Proportion breakdown: use `-a prop` or `-a p`. Compute a proportion breakdown of values at a given node in the JSON. Valid for discrete values only.
- Time serie: use `-a time` or `-a t`. Shows a time-serie plot of values at a given node in the JSON. Use the timestamp on the X axis.

Two other important options are:
- `-e` to filter on a specific type of event.
- `-n` which specify on which node of the JSON the analysis should be performed.

Run `./tcpsnitch\_analyzer -h` for more information about usage.

## Installation

- Requires Ruby 2.x
- Uses bundle for dependencies: `gem install bundler` to install bundle, and `bundle install` to download Ruby dependencies.
- Requries gnu-plot: `sudo apt-get install gnu-plot` to install gnu-plot.
