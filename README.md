# Lancet

**Lancet** is a formal framework for exploit analysis on **Intel Pin** and **QEMU** traces. It enables runtime memory ownership tracking, vulnerability analysis, and exploit primitive detection.

## Repository Structure

This repository maintains two implementations:

| Branch | Description |
|--------|-------------|
| `develop` | QEMU-based implementation (active development branch) |
| `pin-4.2` | Intel Pin 4.2–based implementation |

## Getting Started

Clone the repository:

```bash
git clone https://github.com/a85tract/Lancet.git
```

Switch to the desired implementation:

```bash
# QEMU backend
git checkout develop

# Intel Pin backend
git checkout pin-4.2
```

## Artifact Evaluation

The artifact evaluation package used in our paper is maintained in a separate repository:

**https://github.com/a85tract/Lancet-AE**

## License

Apache License 2.0.

## Citation

If you use **Lancet** in your research or build upon this project, please cite our paper:

> **Lancet: A Formalization Framework for Crash and Exploit Pathology**  
> Qinrun Dai, Kirby Linvill, Yueqi Chen, and Gowtham Kaki.  
> *34th USENIX Security Symposium (USENIX Security '25)*, 2025.

```bibtex
@inproceedings{dai2025lancet,
  title     = {Lancet: A Formalization Framework for Crash and Exploit Pathology},
  author    = {Qinrun Dai and Kirby Linvill and Yueqi Chen and Gowtham Kaki},
  booktitle = {Proceedings of the 34th USENIX Security Symposium (USENIX Security '25)},
  year      = {2025},
}
```
