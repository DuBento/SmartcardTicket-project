package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Date;
import java.security.GeneralSecurityException;


/**
 * Changes after demo:
 *
 * - Removed UID from MAC
 * - Removed read protection from pages, now only write protected
 * - Renamed gift and normal card to unactive and active card
 * - Put counter init state in MAC
 * - Amount of rides and expirty time visible when issuing and validating
 * 
 */
public class Ticket {

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();

    private static final byte[] authenticationKey = "NS-KEYPROJ#1->21".getBytes(); // 16-byte key
    private static final byte[] hmacKey = "NS-MACPROJ#1->21".getBytes(); // 16-byte key
    private static final byte[] hashKey = "NS-SHAPROJ#1->21".getBytes(); // 16-byte key

    public static byte[] data = new byte[192];

    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static TicketMac hashAlgorithm; // For computing hash for auth and HMAC keys
    private static Utilities utils;
    private static Commands ul;

    private byte[] uid = null;
    private byte[] userData = null;
    private byte[] MAC = null;
    private int expiryTime;
    private short maxRides;
    private short counter = -1;

    enum Type {
        ACTIVE,
        UNACTIVE
    }

    private static final short MAX_RIDE = 5;
    private static final int VALIDITY_PERIOD = 1; // in minutes

    private static final short USER_DATA_START_PAGE = 39;
    private static final short MAX_RIDE_PAGE = USER_DATA_START_PAGE;
    private static final short COUNTER_INIT_STATE_PAGE = MAX_RIDE_PAGE - 1;
    private static final short EXPIRY_TIME_PAGE = MAX_RIDE_PAGE - 1;
    private static final short MAC_UNACTIVE_PAGE = EXPIRY_TIME_PAGE - 1;
    private static final short MAC_ACTIVE_PAGE = MAC_UNACTIVE_PAGE - 1;
    private static final short FIRST_USED_PAGE = MAC_ACTIVE_PAGE; // always update this to the last used page, for auth protection

    private static final short COUNTER_PAGE = 41;
    private static final short KEY_PAGE = 44;

    private static String infoToShow = "-"; // Use this to show messages

    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        // Set key for all key generations
        hashAlgorithm = new TicketMac();
        hashAlgorithm.setKey(hashKey);

        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();

        ul = new Commands();
        utils = new Utilities(ul);
    }

    private void setMacKey() throws GeneralSecurityException {
        if (macAlgorithm.isKeySet()) return;

        // MAC key calculated based on UID
        byte[] macKey = calculateHashedKey(hmacKey);
        macAlgorithm.setKey(macKey);
    }

    /** After validation, get ticket status: was it valid or not? If valid return usages */
    public short isValid(Type type) throws GeneralSecurityException {
        if (userData == null ||  MAC == null) {
            Utilities.log("Failed to read Data or MAC in writeMac()", true);
            return 0;
        }
        if (!isMacValid(userData)) {
            Utilities.log("Ticket is not valid because MAC is not valid in isValid()", true);
            infoToShow = "Invalid card data. ";
            return 0;
        }
        short uses = getRemainingUses();
        if (uses <= 0) {
            Utilities.log("Ticket is not valid because there is no more uses in isValid()", true);
            infoToShow = "No rides left. ";
            return 0;
        }

        // Only need to check up until this point for unactive cards
        if (type == Type.UNACTIVE) return uses;

        if (getExpiryTime() >= new Date().getTime() / (1000 * 60)) {
            return uses;
        }
        infoToShow = "Expiry time exceeded. ";
        return 0;
    }

    private boolean isMacValid(byte[] userData) throws GeneralSecurityException {
        byte[] subMac = calculateMac(userData);
        return Arrays.equals(subMac, this.MAC);
    }

    /** After validation, get the number of remaining uses */
    public short getRemainingUses() {
        short counter = readCounter();
        if (counter == -1) {
            Utilities.log("Failed to read counter in setMaxRides()", true);
            return -1;
        }

        if (maxRides != 0) {
            return (short) (maxRides - counter);
        }

        byte[] message = new byte[4];

        boolean res = utils.readPages(MAX_RIDE_PAGE, 1, message, 0);
        if (!res) {
            Utilities.log("Failed to read max rides in setMaxRides()", true);
            return 0;
        }

        byte[] maxRideBytes = Arrays.copyOfRange(message, 0, 2);
        ByteBuffer wrapped = ByteBuffer.wrap(maxRideBytes);
        wrapped.order(ByteOrder.LITTLE_ENDIAN);
        short maxRides = wrapped.getShort();

        return (short) (maxRides - counter);
    }

    /** After validation, get the expiry time */
    public int getExpiryTime() {
        if (expiryTime != 0) {
            return expiryTime;
        }

        byte[] message = new byte[4];

        boolean res = utils.readPages(EXPIRY_TIME_PAGE, 1, message, 0);
        if (!res) {
            Utilities.log("Failed to read expiryTime in getExpiryTime()", true);
            return 0;
        }

        ByteBuffer wrapped = ByteBuffer.wrap(message);
        return wrapped.getInt();
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        return infoToShow;
    }

    private byte[] calculateMac(byte[] userData)  throws GeneralSecurityException {
        this.setMacKey();

        byte[] mac = macAlgorithm.generateMac(userData);

        // Format MAC to write
        byte[] subMac = new byte[4];
        System.arraycopy(mac, 0, subMac, 0, subMac.length);
        return subMac;
    }

    private byte[] calculateHashedKey(byte[] key) {
        if(this.uid == null) {
            this.uid = readUid();
            if (this.uid == null) {
                Utilities.log("Failed to read UID in calculateHashedKey()", true);
                return null;
            }
        }

        byte[] hashData = new byte[key.length + uid.length];
        System.arraycopy(key, 0, hashData, 0, key.length);
        System.arraycopy(uid, 0, hashData, key.length, uid.length);
        byte[] hash = hashAlgorithm.generateMac(hashData);

        // Format Hash to write. Key is 16 bytes
        byte[] subHash = new byte[16];
        System.arraycopy(hash, 0, subHash, 0, subHash.length);
        return subHash;
    }


    private boolean enablePageRestriction(int startPage) {
        boolean res;

        // Define pages to be protected
        byte[] auth0 = new byte[]{(byte) startPage, (byte) 0x00, (byte) 0x00, (byte) 0x00}; // only first bit matters, others added as padding to use writePage()
        res = utils.writePages(auth0,0, 42, 1);
        if (!res) {
            Utilities.log("Enabling Auth0 r/w protection in enablePageRestriction()", true);
            return false;
        }

        // Enable protection of pages defined in Auth0 (write protected only)
        byte[] auth1 = new byte[]{(byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00}; // only first bit matters, others added as padding to use writePage()
        res = utils.writePages(auth1,0, 43, 1);
        if (!res) {
            Utilities.log("Enabling Auth1 write protection in enablePageRestriction()", true);
            return false;
        }

        return true;
    }

    private boolean setMaxRides(short rideCount, boolean addPreviousRides) {
        infoToShow = "Setting Max Rides";

        short counter = readCounter();
        if (counter == -1) {
            Utilities.log("Failed to read the counter in setMaxRides()", true);
            return false;
        }

        short extra = 0;
        if (addPreviousRides) extra = (short) Math.max(getRemainingUses(), 0);

        short maxRideCounter = (short) (counter + rideCount + extra);


        // Format message to be written in page
        byte[] rideCounterBytesShort = Utilities.shortToByteArray(maxRideCounter);
        byte[] rideCounterBytes = {0x0, 0x0, 0x0, 0x0};
        System.arraycopy(rideCounterBytesShort, 0, rideCounterBytes, 0, rideCounterBytesShort.length);

        boolean res = utils.writePages(rideCounterBytes, 0, MAX_RIDE_PAGE, 1);
        if (!res) {
            Utilities.log("Failed to write max rides number in setMaxRides()", true);
            return false;
        }
        infoToShow = "Max Rides set succesfully";
        return true;
    }

    private boolean setExpiryTime(int period) {
        boolean res;

        infoToShow = "Setting up expiry time";

        int expiryTime = (int) (new java.util.Date().getTime() / (1000 * 60)) + period; // in minutes

         // Format message to be written in page
        byte[] expiryTimeBytes = ByteBuffer.allocate(4).putInt(expiryTime).array();

        res = utils.writePages(expiryTimeBytes, 0, EXPIRY_TIME_PAGE, 1);
        if (!res) {
            Utilities.log("Failed to expiry time in setExpiryTime()", true);
            return false;
        }

        infoToShow = "Succesfully set up ExpiryTime";
        this.expiryTime = expiryTime;
        return true;
    }

    private boolean writeKey(byte[] key) {
        infoToShow = "Writing new Auth Key";

        // Write key
        boolean res = utils.writePages(key, 0, KEY_PAGE, 4);
        if (!res) {
            Utilities.log("Failed to write key in writeKey()", true);
            return false;
        }

        return true;
    }

    private boolean writeMac(Type type) throws GeneralSecurityException {
        infoToShow = "Writing MAC";

        userData = readData(type);

        if (userData == null) {
            Utilities.log("Failed to read Data in writeMac()", true);
            return false;
        }

        byte[] subMac = calculateMac(userData);

        // Write MAC
        short pageAddr = (type == Type.UNACTIVE ? MAC_UNACTIVE_PAGE : MAC_ACTIVE_PAGE);
        boolean res = utils.writePages(subMac, 0, pageAddr, 1);
        if (!res) {
            Utilities.log("Failed to write MAC in writeMac()", true);
            return false;
        }

        infoToShow = "Succesfully written MAC";
        return true;
    }

    private byte[] readUid() {
        boolean res;

        infoToShow = "Reading UID";

        byte[] uid = new byte[8];
        res = utils.readPages(0, 2, uid , 0);
        if (!res) {
            Utilities.log("Failed to read uid in readUid()", true);
            return null;
        }

        return uid;
    }

    private byte[] readData(Type type) {
        boolean res;

        infoToShow = "Reading data on " + type.name();

        int numPage;
        short startPage;
        if (type == Type.ACTIVE) {
            numPage = MAX_RIDE_PAGE - EXPIRY_TIME_PAGE + 1;
            startPage = EXPIRY_TIME_PAGE;
        } else {
            numPage = MAX_RIDE_PAGE - COUNTER_INIT_STATE_PAGE + 1; // MAX_RIDE_PAGE and COUNTER_INIT_STATE_PAGE
            startPage = COUNTER_INIT_STATE_PAGE;
        }

        byte[] data = new byte[numPage * 4];
        res = utils.readPages(startPage, numPage, data, 0);
        if (!res) {
            Utilities.log("Failed to read data in readData()", true);
            return null;
        }

        byte[] maxRideBytes = new byte[2];
        System.arraycopy(data, numPage*4 - 4, maxRideBytes, 0, 2);
        ByteBuffer wrapperRides = ByteBuffer.wrap(maxRideBytes);
        wrapperRides.order(ByteOrder.LITTLE_ENDIAN);
        this.maxRides = wrapperRides.getShort();

        if (type == Type.ACTIVE) {
            byte[] expiryTimeBytes = new byte[4];
            System.arraycopy(data, 0, expiryTimeBytes, 0, 4);
            ByteBuffer wrapper = ByteBuffer.wrap(expiryTimeBytes);
            this.expiryTime = wrapper.getInt();
        }

        return data;
    }

    private byte[] readMac(Type type) {
        boolean res;

        infoToShow = "Reading MAC";

        byte[] mac = new byte[4];
        short pageAddr = (type == Type.UNACTIVE ? MAC_UNACTIVE_PAGE : MAC_ACTIVE_PAGE);
        res = utils.readPages(pageAddr, 1, mac, 0);
        if (!res) {
            Utilities.log("Failed to read data in readMac()", true);
            return null;
        }

        return mac;
    }

    /** Read 16bit counter. Value is stored as little endian*/
    private short readCounter() {
        if (this.counter != -1) return this.counter;

        byte[] message = new byte[4];
        boolean res = utils.readPages(COUNTER_PAGE, 1, message, 0);
        if (!res) {
            Utilities.log("Failed to read counter in readCounter()", true);
            return -1;
        }

        // Calculate new ride counter to be stored
        byte[] counterBytes = Arrays.copyOfRange(message, 0, 2);
        ByteBuffer wrapped = ByteBuffer.wrap(counterBytes);
        wrapped.order(ByteOrder.LITTLE_ENDIAN);

        return wrapped.getShort();
    }

    private short readCounterInitState() {
        byte[] message = new byte[4];
        boolean res = utils.readPages(COUNTER_INIT_STATE_PAGE, 1, message, 0);
        if (!res) {
            Utilities.log("Failed to read counter in readCounterInitState()", true);
            return -1;
        }

        // Calculate new ride counter to be stored
        byte[] counterBytes = Arrays.copyOfRange(message, 0, 2);
        ByteBuffer wrapped = ByteBuffer.wrap(counterBytes);
        wrapped.order(ByteOrder.LITTLE_ENDIAN);

        return wrapped.getShort();
    }

    private boolean writeCounterState() {
        byte[] message = new byte[4];
        boolean res = utils.readPages(COUNTER_PAGE, 1, message, 0);
        if (!res) {
            Utilities.log("Failed to read counter in writeCounterState()", true);
            return false;
        }

        // Write counter init state
        res = utils.writePages(message, 0, COUNTER_INIT_STATE_PAGE, 1);
        if (!res) {
            Utilities.log("Failed to write counter state in writeCounterState()", true);
            return false;
        }

        return true;
    }

    private boolean incrementCounter() {
        byte[] increment = {0x01, 0x0, 0x0, 0x0};
        boolean res = utils.writePages(increment, 0, COUNTER_PAGE, 1);
        if (!res) {
            Utilities.log("Failed to increment counter in incrementCounter()", true);
            return false;
        }
        return true;
    }

    private boolean validateUnactiveCard() throws GeneralSecurityException {
        // Check if valid issued ticket
        if (!isMacValid(userData)) {
            Utilities.log("Invalid MAC checked in validateUnactiveCard()", true);
            return false;
        }

        // Write time
        boolean res = setExpiryTime(VALIDITY_PERIOD);
        if (!res) {
            Utilities.log("Failed to set the expiry time in validateUnactiveCard()", true);
            return false;
        }

        // Compute new MAC
        res = writeMac(Type.ACTIVE);
        if (!res) {
            Utilities.log("Write MAC failed in validateUnactiveCard()", true);
            return false;
        }
        return true;
    }

    /**
     * Issue new tickets
     */
    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        infoToShow = "Starting issueing";
        resetInstance();

        boolean res;
        Type cardType;
        boolean addPreviousRides = false;

        // Authenticate for non default should be more used so comes first
        byte[] calculatedKey = calculateHashedKey(authenticationKey);
        if (calculatedKey == null) {
            Utilities.log("Calculating auth key failed in issue()", true);
            infoToShow = "Calculating auth key failed";
            return false;
        }

        res = utils.authenticate(calculatedKey);
        if (!res) {
            // Try authenticate with default key for blank cards
            boolean resDefault = utils.authenticate(defaultAuthenticationKey);
            if (!resDefault) {
                Utilities.log("Authentication failed in issue()", true);
                infoToShow = "Authentication failed";
                return false;
            }
            
            // Write new key
            boolean resKey = writeKey(calculatedKey);
            if (!resKey) {
                Utilities.log("Writing new key failed in issue()", true);
                infoToShow = "Writing new key failed";
                return false;
            }

            // Enable r/w only with authentication
            res = enablePageRestriction(FIRST_USED_PAGE);   // only block the ones need but be careful to block also lock bits for that pages
            if (!res) {
                Utilities.log("Enable page restriction failed in issue()", true);
                infoToShow = "Enable page restriction failed";
                return false;
            }

            // Set as new card
            addPreviousRides = false;
        } else {
            // In case of a card already in use

            // Read whats need for later validation
            this.uid = readUid();

            // Try for active card
            this.userData = readData(Type.ACTIVE);
            this.MAC = readMac(Type.ACTIVE);
            if (isValid(Type.ACTIVE) > 0) {
                // Active card is valid
                addPreviousRides = true;
                Utilities.log("Old ticket is valid as ACTIVE card in issue.", false);
            } else {
                // Not active card
                // Try then for UNACTIVE card
                this.userData = readData(Type.UNACTIVE);
                this.MAC = readMac(Type.UNACTIVE);
                if (isValid(Type.UNACTIVE) > 0) {
                    // Issued but not yet used card
                    addPreviousRides = true;
                    Utilities.log("Old ticket is valid as UNACTIVE card in issue.", false);
                } else {
                    // Old ticket not valid anymore, treated as new
                    Utilities.log("Ticket is not valid in issue. Issuing new ticket.", false);
                    addPreviousRides = false;
                }
            }
        }

        // Read regardless if its a active card or unactive (or new)
        this.uid = readUid();

        // Write data
        res = setMaxRides(MAX_RIDE, addPreviousRides);
        if (!res) {
            Utilities.log("Set max rides failed in issue()", true);
            infoToShow = "Set max rides failed";
            return false;
        }

        res = writeCounterState();
        if (!res) {
            Utilities.log("Write counter state failed in issue()", true);
            infoToShow = "Write counter state failed";
            return false;
        }

        // Empty global variables so we read new written values
//        this.uid = null;
        this.userData = null;

        // MAC key calculated based on UID
        setMacKey(); // only performed if no key there already 
        
        // MAC of unchangeable data
        res = writeMac(Type.UNACTIVE);
        if (!res) {
            Utilities.log("Write MAC failed in issue()", true);
            infoToShow = "Write MAC failed";
            return false;
        }

        int amntRides = getRemainingUses();

        infoToShow = "Succesfully issued\nNew amount of rides available: " + amntRides;
        return true;
    }

    /**
     * Use ticket once
     */
    public boolean use() throws GeneralSecurityException {
        infoToShow = "Starting validation";
        resetInstance();

        boolean res;
        Type type = Type.ACTIVE;

        // Authenticate
        byte[] calculatedKey = calculateHashedKey(authenticationKey);
        if (calculatedKey == null) {
            Utilities.log("Calculating auth key failed in use()", true);
            infoToShow = "Calculating auth key failed";
            return false;
        }

        res = utils.authenticate(calculatedKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        short counter = readCounter();
        short counterInitState = readCounterInitState();
        if (counter == counterInitState) type = Type.UNACTIVE;

        // Read whats need for later validation
        this.userData = readData(type);
        this.uid = readUid();
        this.MAC = readMac(type);
        if (userData == null || uid == null || MAC == null) {
            Utilities.log("Failed to read Uid or Data or MAC in writeMac()", true);
            return false;
        }

        if (type == Type.UNACTIVE) {
            res = validateUnactiveCard();
            if (!res) {
                Utilities.log("Failed to validate unactive card in use()", true);
                infoToShow = "Failed to validate unactive card";
                return false;
            }

            // Read new data now as active card to later validate
            this.userData = readData(Type.ACTIVE);
            this.MAC = readMac(Type.ACTIVE);
            if (userData == null || MAC == null) {
                Utilities.log("Failed to read Uid or Data or MAC in writeMac()", true);
                return false;
            }
        }

        short usages = isValid(Type.ACTIVE);
        if (usages > 0) {
            res = incrementCounter();
            if (!res) {
                Utilities.log("Failed to increment counter in use()", true);
                infoToShow = "Failed to increment counter";
            }
            SimpleDateFormat sdf = new SimpleDateFormat("HH:mm");

            infoToShow = "Rides left: " + (usages-1) +'\n' + "Expiry time: " + sdf.format(new Date((long) expiryTime * 60 * 1000));

            return true;
        } else {
            return false;
        }
    }

    private void resetInstance() {
        this.counter = -1;
        this.expiryTime = -1;
        this.maxRides = -1;
        this.uid = null;
        this.userData = null;
        this.MAC = null;
        macAlgorithm = new TicketMac();
//        macAlgorithm.unsetKey();
    }
}