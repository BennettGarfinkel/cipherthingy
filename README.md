TODO: fix null character issue
possible fixes, 
switch order of encryption/decryption. Issue: likely cannot encrypt null characters
when ascii code goes below 32, go back up to 255, and vice versa Issues: annoying to implement
