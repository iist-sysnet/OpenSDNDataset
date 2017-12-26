# README #

This is a SDN specific dataset generation tool. Given an SDN
controller, the project runs the network simulations with various
traffic patterns for a defined number of seconds, generates the packet
capture as a dataset sample. This process is repeated as many times as
needed to generate an SDN packet trace dataset.

## REQUIREMENTS ##

1. Mininet VM
2. Python2.7
3. RYU SDN Controller

## FILES ##

## mininet_1.py

This is the mininet network simulation code. This performs the
following functions:

1. Create a Random Topology.
2. Populates switches and hosts in the topology. The switches are
   connected to the user-defined SDN controllers.
3. Runs the random traffic generator for a set duration.

## Controllers/<controller_codes>

The controllers are run in parallel with mininet. The controllers may
be designed by the user as they wish. Three example controllers are
provided with the project.

## pyscript.py

This is the overall scheduler for the dataset creation process. It
calls mininet_1.py, calls the controller based on the schedule
programmed in this file and
keeps the processes alive for the simulation period. Post which, if the
processes don't terminate automatically, are killed completely to set
up a clean slate for next iteration.

## USAGE

* The location for the dataset to be created has to be specified in
pyscript.py.

* Similarly the location of the controllers have to be specifed.

* The existing code uses ryu controllers, however, any controller
  could be used and the command to call the controller has to be
  specified in pyscript.py
  
* Simulation period has to be specified in mininet_1.py.

* The user has to decide how to run each controller if there are
  multiple controllers to choose from, this should go into
  pyscript.py. Currently, a round-robin example is provided.
  
* The user decision as to which switch goes under which controller
  goes under mininet_1.py.
  
* Desired number of samples in the dataset has to be configured in pyscript.py
  
  
Upon setting the above parameters, the dataset generations begins with
a simple command.

**python pyscript.py**


