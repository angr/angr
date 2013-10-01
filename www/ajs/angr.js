//
// AngularJS stuff
//

angr_url = "http://localhost:5000"

/////////////////////////
// Route configuration //
/////////////////////////
var amod = angular.module('angr', ['ui.bootstrap']);
amod.config(['$routeProvider', function($routeProvider) {
	$routeProvider.
		when('/', {templateUrl: 'ajs/index.html', controller: IndexCtrl}).
		when('/open', {templateUrl: 'ajs/open.html', controller: OpenCtrl}).
		when('/bin', {templateUrl: 'ajs/bin.html', controller: BinCtrl}).
		otherwise({redirectTo: '/'});
}]);

///////////
// Index //
///////////
function IndexCtrl($scope, $routeParams)
{
}

//////////
// Open //
//////////
function OpenCtrl($scope, $routeParams, $http)
{
	$scope.alerts = [ ]

	$scope.open_bin = function(filename)
	{
		var notification = {type: 'info', msg: filename + ": loading..."};
		$scope.alerts.push(notification);
		$http.jsonp(angr_url + "/load_binary?callback=JSON_CALLBACK", {params: {bin_name: filename, filename: filename}}).success(function(data, status)
		{
			notification.type = 'success';
			notification.msg = filename + ": " + data + "!";
			$scope.list_binaries();
		}).error(function(data, status)
		{
			notification.type = 'danger';
			notification.msg = filename + ": " + status + " error: " + data;
		});
	}

	$scope.binaries = [ ]

	$scope.list_binaries = function()
	{
		$http.jsonp(angr_url + "/list_binaries?callback=JSON_CALLBACK").success(function(data, status)
		{
			$scope.binaries = data;
		}).error(function(data, status)
		{
			$scope.alerts.push({type: 'danger', msg: status + " error listing binaries: " + data});
		});
	}

	$scope.list_binaries();
}

/////////
// Bin //
/////////
function BinCtrl($scope, $routeParams, $http)
{
	$scope.bin_name = $routeParams.bin_name;
	$scope.functions = [ ];

	$scope.list_binaries = function()
	{
		$http.jsonp(angr_url + "/list_functions?callback=JSON_CALLBACK", {params: {bin_name: $scope.bin_name}}).success(function(data, status)
		{
			$scope.functions = data;
		}).error(function(data, status)
		{
			$scope.alerts.push({type: 'danger', msg: status + " error listing functions: " + data});
		});
	}

	$scope.list_binaries();
}
