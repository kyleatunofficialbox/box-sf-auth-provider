public class BoxUserResponse {

	public String id;
	public String type;
	public String login;
	public String name;

	
	public static BoxUserResponse parse(String json) {
		return (BoxUserResponse) System.JSON.deserialize(json, BoxUserResponse.class);
	}
}