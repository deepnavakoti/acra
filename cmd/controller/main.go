// Command controller runs the ACRA operator: it watches AgentPolicy objects and
// reflects live drift (from the apiserver) into their status. This is the
// Kubernetes-native brain — the cluster reports drift on its own.
package main

import (
	"os"

	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"

	acrav1 "github.com/deepnavakoti/acra/api/v1alpha1"
	"github.com/deepnavakoti/acra/internal/controller"
)

func main() {
	ctrl.SetLogger(zap.New(zap.UseDevMode(true)))
	log := ctrl.Log.WithName("acra-controller")

	scheme := runtime.NewScheme()
	_ = clientgoscheme.AddToScheme(scheme)
	_ = acrav1.AddToScheme(scheme)

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme})
	if err != nil {
		log.Error(err, "unable to start manager")
		os.Exit(1)
	}

	apiserver := os.Getenv("APISERVER_URL")
	if apiserver == "" {
		apiserver = "http://acra-apiserver.acra-system.svc"
	}

	if err := (&controller.AgentPolicyReconciler{
		Client:    mgr.GetClient(),
		Scheme:    mgr.GetScheme(),
		APIServer: apiserver,
		Token:     os.Getenv("ACRA_API_TOKEN"),
	}).SetupWithManager(mgr); err != nil {
		log.Error(err, "unable to create controller")
		os.Exit(1)
	}

	log.Info("starting acra-controller", "apiserver", apiserver)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		log.Error(err, "manager exited")
		os.Exit(1)
	}
}
