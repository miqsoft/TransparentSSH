# TransparentSSH

A collection of tools/scripts to evaluate SSH traffic analyis methods.
It contains:
 - /ZeekScripts/ssh_zeek_satoh.zeek : script, that detects authentication methods based upon the research from Satoh et al. ([paper](https://ieeexplore.ieee.org/abstract/document/6605856))
 - /ZeekDocker : a docker container, that analyzes a set of pcaps and creates logs for SSH (uses also the script above)