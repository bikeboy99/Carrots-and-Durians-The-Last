1.
Davis Burton -at
Soohwang (Paul) Yeem -nd

2. 
Some problems/challenges that we faced were:
-Designing the control path
We had to change our intended implementation several times because of this.
At first we thought that a packet's path to handle_monitorData was connectionIn -> deferredConnection -> monitorData.
A case we missed was it was possible to go to monitorData from connectionIn, so monitorData needed to handle both cases
instead of assuming that every connection that came to monitorData came from deferredConnection

-Regex matching for part 3
Until we read from Piazza that we can store O(sum of match strings) in the buffer,
we were trying to only work with having O(largest match string), storing inbound and outbound "buffer" in a wrapper class.
For the test case on Piazza with 180 'a's, we were failing because we only kept 1 "buffer" for all search strings, and there were cases that 
When we realized above, we instead made a dictionary for each substring that stores respective buffer for each match string.
Realizing the above fact made our lives MUCH MUCH EASIER.

-Storing and updating timer properly
One bug that we caught last was having a "dangling" timer. 
There was a case that a timer never got cancelled (though we reset with a new timer for a connection),
so our firewall was crashing because we were trying to clean up something that was already cleaned.  
We cancelled and got rid of the old timer when a connection was rereshed. 
