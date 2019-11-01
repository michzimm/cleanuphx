# HyperFlex Clean-up Python Script aka "cleanuphx"

## Purpose

Completely reset a HyperFlex cluster in preparation for a new installation.

## !!!Warning!!!

This script will DELETE all virtual machines and data on the HyperFlex cluster and it will not be recoverable. You assume all responsibility and risk when running this script!!

## Caveats

- Supports VMware HyperFlex clusters only
- Does not support Hyper-V HyperFlex clusters
- Supports M4 and M5 Converged nodes only
- Does not support HyperFlex clusters containing Compute-Only nodes

## Installation

Recommended to use a virtual environment, but not mandatory.

1. Install python3.x
2. Install pip
3. Using the provided "requirements.txt" file, run `pip install -r requirements.txt`.

## Setup

1. Manually create a UCS vMedia policy in the "root" UCS Org. The vMedia policy should map to the HyperFlex ESXi ISO that should be installed on the HyperFlex nodes as part of the reset process. The vMedia policy is created in the "root" Org so that it can be reused over and over and is not deleted as part of the reset process.

## Run Script

1. Run `cleanuphx.py`.
2. Enter UCS Manager IP address.
3. Enter UCS Manager username.
4. Enter UCS Manager password. (Note: the password is not saved/stored)
5. Enter UCS Org name. This is the UCS Org that corresponds to the installed/existing HyperFlex cluster.
6. Enter UCS vMedia policy name. This is the vMedia policy created above in the "Setup" section.
7. Enter the vCenter Server IP address.
8. Enter the vCenter Server username.
9. Enter the vCenter Server password. (Note: the password is not saved/stored)
10. Enter the vCenter Server VMware Datacenter name. This is the VMware Datacenter that corresponds to the installed/existing HyperFlex cluster.
11. Enter the vCenter Server VMware Cluster name. This is the VMware Cluster that corresponds to the installed/existing HyperFlex cluster.

## Example

![Screen Shot 2019-03-27 at 4 03 04 PM](https://user-images.githubusercontent.com/24229893/55111136-0af7f800-50b0-11e9-9acf-8bf06426d383.png)
![Screen Shot 2019-03-27 at 4 03 34 PM](https://user-images.githubusercontent.com/24229893/55111162-1ea35e80-50b0-11e9-9c67-2937115db6ec.png)
