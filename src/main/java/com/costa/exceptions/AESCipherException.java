package com.costa.exceptions;

public class AESCipherException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = -8331508922550679814L;
	
	
	public AESCipherException() {
	
	}
	
	public AESCipherException(Throwable cause) {
		super(cause);
	}

	public AESCipherException(String newMsg, Throwable cause) {
		super(newMsg,cause);
		
	}
	
}
