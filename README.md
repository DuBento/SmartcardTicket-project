- Add issued x
- When does time expire in validate "in x amount of minutes"
- remove unsuc to expire

## From Design Document
- Also, you should remember to set the AUTH1 parameter on the card because, by default, all the
memory pages can be written without authentication.
- Sometimes it is better to write an application-specific ticket identifier on the card and use it for event
logging and key diversification instead of the smart-card UID.
- It is a good idea to reserve one or two pages of the card memory for an application tag and version
number.
- To prevent the MitM attacks on the Ultralight family cards, you can compute a message authentication
code (MAC) over the ticket data on the card, including the card UID, and write the MAC to the card.
- Instead, compute the MAC
only on the issued ticket and exclude the ride counter and other continuously changing data from the
MAC input. For example, the number of remaining rides can be calculated as the difference between the
current counter value and an unchanging maximum value.
- To prevent tearing on the
cheap cards, tapping operations like ticket validation should only do one write operation on the card,
such as writing only one page, or setting only one bit in the OTP, or only incrementing the counter.
- It is a good idea to keep a log of the latest events, such as ticket purchase or use, in the card memory. It
may be sufficient to store basic information such as the date and time, event type, and transaction
amount for the 1-5 latest events. This will help in debugging and resolving problem cases. 


## Spec
- AUTH0 defines the page address from which the authentication is required. Valid
address values for byte AUTH0 are from 03h to 30h.
- Setting AUTH0 to 30h effectively disables memory protection.
- AUTH1 determines if write access is restricted or both read and write access are
restricted, see Table 12


## Ask
- Should we have tearing protection when considering date checks? -- No because we read once, check in reader and only increment counter for rides. Check is performed in reader.
- Are we supposed to change UI to let the user decide how long the ticket is valid?
- Top up with more 5 rides, where's the UI for that? We just use the same issue UI and check if there's a valid ticket there?
- "Start validity when used for the first time". Are we supposed to recalculate a mac and write a date in the first use time?
- Is it required to change the authentication key from the default one?
- Can we change code out of ticket.java?

## Answers
[ ] D-Tearing protection for gift card;
[X] D-Hashed key (UID, master secret);
[x] D-Fix counter
[ ] J-Issue 5 more if still have some there.
[ ] J-Get our own time, smaller;
[ ] J-Informative and short msgs (how many rides left, time to expire)

## Report
mem layout, list sec feutures (how implement) and maybe some decisions

Questions to answer:
- why are we using UID in MAC;

### Replay vulnerability
While the counter can prevent rollback of the card state, it is still possible to relay the earlier card state
from the equipment used in the MitM attack. That is, the attacker reads the card memory after the
ticket was issued. It them emulates card behavior on an FPGA board. Only the authentication is
forwarded to the real card, and all other behavior is emulated.

### Rollback prevention
We increment a monotonic counter so the internal state of the card cannot be reverted.

## Gift Card
Since we need to write more than one page in the first use my first thought was to use OTP pages as a commit transaction protocol to provide rollback protection, but then I check that we cannot write protect the first two lock bytes (they include OTP pages).
So I just realised that we can use the counter as a anti-tearing protection as well.
```
if uses == 5 then:
	its a gift card
else:
	its a normal card
```
We need to store both MACs tho, the page we write is not a problem since it's only one and the previous value doesn't matter. We need to calculate the first MAC without that page tho.
`Gift Card`= MAC(uid, max-rides)
`Normal Card`= MAC(uid, max-rides, expiry time)

### Version and Tag
We store them in unprotected pages because they only serve to know if the card is being used by our application or not. We put them in a unprotected page so we can read before trying to authenticate which is consumes more resources than checking a page.
An attacker could obviously change the data of version+tag but would change anything for us because we are not giving the options of different protocols for the user to work with and so the attacker couldn't try a week protocol.
The alternative would be having to authenticate to check the value but that would break the purpose of storing version+tag since if the authentication works the chance of being a card in use by our application would be very high.
We implement version+tag so that we can present to the app user that the card is not supposed to be working with our app and not only (Authentication failed).

### Different key for Auth and MAC
Even if the auth key is leak for a particular card and they can change data for the particular card it wont be accepted since we are using another key for the MAC.
