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
					context.log("NEW");
				});
				this.get("#/clients/show", function(context){
					var url = "/clients/show"
					Application.Tab.addTab("Configured Clients" , url );
					context.log("NEW");
				});
				this.get("#/clients/stats", function(context){
					var url = "/client/stats"
					Application.Tab.addTab("Clients Statistics" , url );
					context.log("NEW");
				});
				this.get("#/help", function(context){
					context.log("#/help");
					var url = "/help"
					Application.Tab.addTab("Help Page" , url, true);
				});

			});
		},
		run : function(){
			Application.Routing.Sammy.run("#main");
		}
}
