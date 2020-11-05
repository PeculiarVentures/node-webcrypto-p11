import * as graphene from "graphene-pk11";

// tslint:disable-next-line: no-empty-interface
export interface IGlobalOptions {
}

export interface ISessionContainer {
  readonly session: graphene.Session;
  readonly options: IGlobalOptions;
}

export interface IContainer {
  readonly container: ISessionContainer;
}
