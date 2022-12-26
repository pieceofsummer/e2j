# e2j

```
          _         _                   _     
         /\ \     /\ \                 /\ \   
        /  \ \   /  \ \                \ \ \  
       / /\ \ \ / /\ \ \               /\ \_\ 
      / / /\ \_\\/_/\ \ \             / /\/_/ 
     / /_/_ \/_/    / / /    _       / / /    
    / /____/\      / / /    /\ \    / / /     
   / /\____\/     / / /  _  \ \_\  / / /      
  / / /______    / / /_/\_\ / / /_/ / /       
 / / /_______\  / /_____/ // / /__\/ /        
 \/__________/  \________/ \/_______/         
                                              
```

Jar2Exe extraction tool [WIP]

# Supported protection modes

 - None
 - Hide class files
 - Encrypt and hide class files

The latter hashes file names inside archive, so restoring directory structure may be tricky (and not always possible).

But the script is doing its best nevertheless.

# Usage

`./e2j.py file.exe out.jar`

