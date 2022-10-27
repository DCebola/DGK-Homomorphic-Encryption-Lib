package dgk.src.main.misc;

import java.io.Serial;

public class HomomorphicException extends Exception
{
	@Serial
	private static final long serialVersionUID = 8999421918165322916L;

	public HomomorphicException() {
		super();
	}
	
	public HomomorphicException(String message) {
		super(message);
	}
}
