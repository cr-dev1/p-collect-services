package com.costa.exceptions;

public class InvalidPayloadException extends Exception{

	/**
	 * @author sbhaskara
	 */
	private static final long serialVersionUID = -8267333729706048889L;
	
	
	public InvalidPayloadException() {
	
	}
	
	public InvalidPayloadException(Throwable cause) {
		super(cause);
	}

	public InvalidPayloadException(String newMsg, Throwable cause) {
		super(newMsg,cause);
		
	}

}
