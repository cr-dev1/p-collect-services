package com.costa.exceptions;

public class AESDecipherException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = -8331508922550679814L;

	public AESDecipherException() {
	
	}
	
	public AESDecipherException(Throwable cause) {
		super(cause);
	}

	public AESDecipherException(String newMsg, Throwable cause) {
		super(newMsg,cause);
		
	}

	
}
