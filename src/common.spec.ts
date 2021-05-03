import { expect } from 'chai';
import 'mocha';

import { getController } from './common';

const identifer = 'did:web:digitalcredentials.github.io#z6MkrXSQTybtqyMasfSxeRBJxDvDUGqb7mt9fFVXkVn6xTG7';
const controller = 'did:web:digitalcredentials.github.io';

describe('Common test',
  () => {
    it('should parse controller', () => {
      const result = getController(identifer);
      expect(result).to.equal(controller);
    });

  });
