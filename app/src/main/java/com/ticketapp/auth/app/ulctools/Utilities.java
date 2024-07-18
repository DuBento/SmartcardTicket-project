package com.ticketapp.auth.app.ulctools;

/**
 * Developed for Aalto University course CS-E4300 Network Security.
 * Copyright (C) 2021-2022 Aalto University
 */

import android.util.Log;

/**
 * Compatibility class to make Desktop versions of Ticket class methods compatible with the Android application.
 */
public class Utilities {
    Commands ul;


    public Utilities(Commands ul) {
        this.ul = ul;
    }
    /**
     * Try to erase card content from page 4 to page 39.
     *
     * @return boolean value of success
     */
    public boolean eraseMemory() {
        Reader.erase(false);
        return true;
    }

    /**
     * Read the card memory to a given array with authentication or without authentication.
     *
     * @return byte array where the data is stored
     */
    public byte[] readMemory() {
        byte[] memory = new byte[192];
        readPages(0, 44, memory, 0);
        return memory;
    }


    /**
     * Read card memory from starting page for defined amount of pages
     *
     * @param startPage            start page of read
     * @param numberOfPages        how many pages to read
     * @param destination          where to store received data
     * @param destinationStartByte at what point to store received data
     * @return boolean value of success
     */
    public boolean readPages(int startPage, int numberOfPages, byte[] destination, int destinationStartByte) {
        // We always read and write one 4-byte page at a time.
        // The address is the number 0...39 of the 4-byte page.
        for (int i = 0; i < numberOfPages; i++) {
            boolean status = ul.readBinary(startPage + i, destination,
                    destinationStartByte + i * 4);
            if (!status) {
                return false;
            }
        }
        return true;

    }

    /**
     * Write input byte array on card
     *
     * @param srcBuffer     byte array
     * @param srcPos        starting point of data to write
     * @param startPage     first page on card to write data
     * @param numberOfPages how many pages to write
     * @return boolean value of success
     */
    public boolean writePages(byte[] srcBuffer, int srcPos, int startPage, int numberOfPages) {
        boolean status;
        // We always read and write one 4-byte page at a time.
        // The address is the number 0...39 of the 4-byte page.
        for (int i = 0; i < numberOfPages; i++) {
            status = ul.writeBinary(startPage + i, srcBuffer, srcPos + 4
                    * i);
            if (!status) {
                return false;
            }
        }
        return true;
    }

    /**
     * Authenticate card with given key in stored in byte array
     *
     * @param key byte array that contains the key
     * @return boolean value of success
     */
    public boolean authenticate(byte[] key) {
        return Reader.authenticate(key, true);
    }

    /**
     * Log for debugging with Android Studio
     *
     * @param message message to log
     * @param error true if caused by an error, false if not
     */
    public static void log(String message, boolean error) {
        if (error)
            Log.e("Error", message);
        else
            Log.i("Debug", message);
    }

    /** Helper function to convert from short to byte array. LittleEndian */
    public static byte[] shortToByteArray(short n) {
        byte[] arr = new byte[2];
        arr[0] = (byte)(n & 0xff);
        arr[1] = (byte)((n >> 8) & 0xff);
        return arr;
    }

    /** Helper function to convert from long to byte array. BigEndian */
    public static byte[] longtoByteArray(long data) {
        return new byte[]{
                (byte) ((data >> 56) & 0xff),
                (byte) ((data >> 48) & 0xff),
                (byte) ((data >> 40) & 0xff),
                (byte) ((data >> 32) & 0xff),
                (byte) ((data >> 24) & 0xff),
                (byte) ((data >> 16) & 0xff),
                (byte) ((data >> 8) & 0xff),
                (byte) (data & 0xff),
        };
    }

    /** Helper function to print byte array as Hex */
    public static void printHex(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (byte aByte : data) {
            result.append(String.format("%02x", aByte));

        }
        System.out.println(result.toString());
    }
}
