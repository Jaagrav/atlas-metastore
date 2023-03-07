import java.net.http.HttpClient;

public class SSRF extends HttpServlet {
	private static final String VALID_URI = "http://lgtm.com";
	private HttpClient client = HttpClient.newHttpClient();

	protected void doGet(HttpServletRequest request, HttpServletResponse response)
		throws ServletException, IOException {
		URI uri = new URI(request.getParameter("uri"));
		// BAD: a request parameter is incorporated without validation into a Http request
		HttpRequest r = HttpRequest.newBuilder(uri).build();
		client.send(r, null);


	}
}
