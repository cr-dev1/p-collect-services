package com.costa.exceptions;

public class XSalsaCipherException extends Exception{

	/**
	 * 
	 */
	private static final long serialVersionUID = -8331508922550679814L;

	
	public XSalsaCipherException() {
	
	}
	
	public XSalsaCipherException(Throwable cause) {
		super(cause);
	}

	public XSalsaCipherException(String newMsg, Throwable cause) {
		super(newMsg,cause);
		
	}
	
}
