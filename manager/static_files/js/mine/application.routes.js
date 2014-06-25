var Application = window.Application || {};
Application.Routing = {
		Configure : function(){
			Application.Routing.Sammy = $.sammy("#main", function(){
				this.get("#main", function(context){
					context.log("MAIN");
					
				});
				this.get("#/clients/add", function(context){
					var url = "/clients/add"
					Application.Tab.addTab("New Client Add" , url );
					context.log("ADD");
				});
				this.get("#/clients/show", function(context){
					var url = "/clients/show";
					Application.Tab.addTab("Configured Clients" , url );
					context.log("MUL SHOW");
				});
				this.get("#/clients/show/:ID", function(context){
					url = "/clients/show/" + this.params['ID']
					Application.Tab.addTab("Cient Details : " + this.params['ID'] , url );
					context.log("SING SHOW");
				});
				this.get("#/clients/stats", function(context){
					var url = "/clients/stats"
					Application.Tab.addTab("Clients Statistics" , url );
					context.log("STATS");
				});
				this.get("#/about", function(context){
					context.log("#/about");
					var url = "/about"
					Application.Tab.addTab("About Page" , url, true);
				});

			});
		},
		run : function(){
			Application.Routing.Sammy.run("#main");
		}
}
