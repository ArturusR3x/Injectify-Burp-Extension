package burp;

public class RemoveQuotes implements  IHttpListener{

	private IBurpExtenderCallbacks callbacks;
	public RemoveQuotes(IBurpExtenderCallbacks callbacks){
		this.callbacks = callbacks;
		callbacks.registerHttpListener(this);
	}
	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (messageIsRequest) {
			IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
			byte[] request = messageInfo.getRequest();
			String requestStr = new String(request);
			// Remove double quotes from the request
			String modifiedRequest = requestStr.replaceAll("\"", "");
			// Update the request with modified content
			messageInfo.setRequest(modifiedRequest.getBytes());
		}
	}

}
