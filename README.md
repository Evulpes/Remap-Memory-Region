# Remap-Memory-Region
Basic example of how to change the initial rights on a memory region during runtime.

As this code is getting some traction, please note that this sample does very little error checking, or cleanup of resources. You will need to implement these if you plan to use this sample for anything. 

Please note that the AllocationProtect flag of MEMORY_BASIC_INFORMATION structure contains the initial rights, so any good anticheat can check if you have changed the initial rights from what they should be.
