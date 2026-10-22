const image=process.argv[2];if(!image?.includes('@sha256:'))throw new Error('Pass an immutable synthetic-demo image');
const ns='mcp-otel-synthetic',metadata=name=>({name,namespace:ns});
console.log(JSON.stringify({apiVersion:'v1',kind:'List',items:[
  {apiVersion:'v1',kind:'Namespace',metadata:{name:ns}},
  {apiVersion:'apps/v1',kind:'Deployment',metadata:metadata('repair-demo'),spec:{replicas:1,selector:{matchLabels:{app:'repair-demo'}},template:{metadata:{labels:{app:'repair-demo','app.kubernetes.io/name':'repair-demo'},annotations:{'prometheus.io/scrape':'true','prometheus.io/port':'8080','prometheus.io/path':'/metrics'}},spec:{automountServiceAccountToken:false,securityContext:{runAsNonRoot:true,runAsUser:1000,runAsGroup:1000,seccompProfile:{type:'RuntimeDefault'}},containers:[{name:'demo',image,env:[{name:'NAMESPACE',value:ns}],ports:[{containerPort:8080}],securityContext:{allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:['ALL']}},resources:{requests:{cpu:'20m',memory:'64Mi'},limits:{memory:'128Mi'}},readinessProbe:{httpGet:{path:'/ready',port:8080},periodSeconds:5}}]}}}},
  {apiVersion:'v1',kind:'Service',metadata:metadata('repair-demo'),spec:{selector:{app:'repair-demo'},ports:[{port:8080,targetPort:8080}]}},
  {apiVersion:'v1',kind:'ServiceAccount',metadata:metadata('repair-worker')},
  {apiVersion:'rbac.authorization.k8s.io/v1',kind:'Role',metadata:metadata('repair-worker'),rules:[{apiGroups:['apps'],resources:['deployments'],resourceNames:['repair-demo'],verbs:['get','patch','watch']}]},
  {apiVersion:'rbac.authorization.k8s.io/v1',kind:'RoleBinding',metadata:metadata('repair-worker'),roleRef:{apiGroup:'rbac.authorization.k8s.io',kind:'Role',name:'repair-worker'},subjects:[{kind:'ServiceAccount',name:'repair-worker',namespace:ns}]}
]},null,2));
