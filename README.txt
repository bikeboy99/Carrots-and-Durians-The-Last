1.
Davis Burton -at
Soohwang (Paul) Yeem -nd

2. 
Some problems/challenges that we faced were:

-stitching packets together
We weren't sure packet stitching was going to be on this project like it was on the last one, so initially we didn't implement packet stitching in our solution.  Luckily we didn't have to change our code too much when we found out stitching had to happen.  Also, the FTP spec that states a \r\n or \n must be on the end of every line was very helpful (otherwise it would have been nearly impossible to know when a line ends!) We went ahead and implemented a buffer for each ftp command connection.  This buffer held any data that wasn't part of a full line yet, so this way we could handle multiple packets with non-full lines.  Once we had a full line, we processed it.

-parsing the lines:
This proved to be a tricky problem that we initially tried to solve without regex.  However, there were so many cases to cover without using a regex that we decided to revamp the code and use some clever regex searches to sort out malformed lines from correct ones.

-timers
Initially, we thought each port only had to have one timer associated with it.  Then we found out that multiple FTPdata connections could queue up for a single open port.  This meant we had to change our dictionary of timers into a dictionary of lists of timers.  We thought we werer going to have to keep count of the number of times a port was opened, but thankfully a 1:1 relation between timers and the opening of a port made it fairly easy to check when the port was closed (no timers left in the list!)